#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <doca_mmap.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dma.h>
#include <doca_sha.h>
#include <doca_graph.h>
#include <doca_types.h>
#include <doca_log.h>

#include <samples/common.h>

#include <pthread.h>


DOCA_LOG_REGISTER(GRAPH::SAMPLE);

/**
 * This sample implements a Pthread version 
 *
 *         +-----+      +-----+
 *         | SHA |      | DMA |
 *         +--+--+      +-----+
 *
 * The sample uses work queue in polling mode for the sake of simplicity.
 */

/**
 * This macro is used to minimize code size.
 * The macro runs an expression and returns error if the expression status is not DOCA_SUCCESS
 */
#define EXIT_ON_FAILURE(_expression_) { \
	doca_error_t _status_ = _expression_; \
	\
	if (_status_ != DOCA_SUCCESS) { \
		DOCA_LOG_ERR("%s failed with status %s", __func__, doca_get_error_string(_status_)); \
		return _status_; \
	} \
}

#define NUM_GRAPH_INSTNACES		1

#define SOURCE_BUFFER_SIZE		1024
#define DMA_DEST_BUFFER_SIZE		SOURCE_BUFFER_SIZE
#define SHA_DEST_BUFFER_SIZE		DOCA_SHA256_BYTE_COUNT

#define REQUIRED_ENTRY_SIZE		(SOURCE_BUFFER_SIZE + DMA_DEST_BUFFER_SIZE + SHA_DEST_BUFFER_SIZE)

#define BUFFER_SIZE			(REQUIRED_ENTRY_SIZE * NUM_GRAPH_INSTNACES)

/* Buffers are: source, DMA destination, SHA value */
#define GRAPH_INSTNACE_NUM_BUFFERS	(3)
#define BUF_INVENTORY_SIZE		(GRAPH_INSTNACE_NUM_BUFFERS * NUM_GRAPH_INSTNACES)

/* Context jobs are: DMA, SHA */
#define NUM_CTX_JOBS_PER_GRAPH_INSTNACE 2

/**
 * Work queue depth should be >= (num graph context nodes + 1 for the graph) * num graph instances.
 * The depth should be larger if the work queue serves stand alone jobs or other graphs.
 */
#define WORK_QUEUE_DEPTH ((NUM_CTX_JOBS_PER_GRAPH_INSTNACE + 1) * NUM_GRAPH_INSTNACES)

/**
 * The sample uses an array of doca_ctx. This enum defines the nodes in the array.
 */
enum sample_contexts {
  SAMPLE_CONTEXT_SHA,
  SAMPLE_CONTEXT_DMA,
  NUM_SAMPLE_CONTEXTS
};

/**
 * It is recommended to put the instance data in a struct.
 * Notice that jobs life span must be >= life span of the instance.
 */
struct graph_instance_data {
  uint32_t index; /* Index is used for printing */
  struct doca_graph_instance *graph_instance;
  struct doca_buf *source;
  uint8_t *source_addr;
  
  struct doca_sha_job sha_job;
  struct doca_event sha_job_event;
  struct doca_buf *sha_dest;
  uint8_t *sha_dest_addr;
  
  struct doca_dma_job_memcpy dma_job;
  struct doca_event dma_job_event;
  struct doca_buf *dma_dest;
  uint8_t *dma_dest_addr;
  
  struct doca_event user_node_event;
};

/**
 * This struct defines the application context.
 */
struct graph_sample_state {
  /**
   * Resources
   */
  struct doca_dev *device;
  struct doca_mmap *mmap;
  struct doca_buf_inventory *inventory;
  struct doca_workq *work_queue;
  struct doca_ctx *contexts[NUM_SAMPLE_CONTEXTS];
  struct doca_sha *sha;
  struct doca_dma *dma;
  
  /**
   * Buffer
   * This buffer is used for the source and destination.
   * Real life scenario may use more memory areas.
   */
  uint8_t *buffer;
  uint8_t *available_buffer; /* Points to the available location in the buffer, used during initialization */
  
  /**
   * Graph
   * This section holds the graph and nodes.
   * The nodes are used during instance creation and maintenance.
   */
  struct doca_graph *graph;
  struct doca_graph_node *sha_node;
  struct doca_graph_node *dma_node;
  struct doca_graph_node *user_node;
  
  /* Array of graph instances. All will be submitted to the work queue at once */
  struct graph_instance_data instances[NUM_GRAPH_INSTNACES];
};


/**
 * Stop contexts
 * The method removes the contexts from the work queue, stops them and removes the device from them.
 *
 * @state [in]: sample state
 */
void stop_contexts(struct graph_sample_state *state) {
  uint32_t i = 0;

  for (i = 0; i < NUM_SAMPLE_CONTEXTS; i++) {
    if (state->contexts[i] != NULL) {
      doca_ctx_workq_rm(state->contexts[i], state->work_queue);
      doca_ctx_stop(state->contexts[i]);
      doca_ctx_dev_rm(state->contexts[i], state->device);
    }
  }
}


/**
 * Destroy
 *
 * @state [in]: sample state
 */
void
destroy_graph(struct graph_sample_state *state) {
  if (state->graph == NULL)
    return;

  doca_graph_workq_rm(state->graph, state->work_queue);
  doca_graph_stop(state->graph);
  doca_graph_destroy(state->graph);
}


/**
 * Destroy instance
 *
 * @state [in]: sample state
 * @index [in]: the instance index
 */
void destroy_graph_instance(struct graph_sample_state *state, uint32_t index) {
  struct graph_instance_data *instance = &state->instances[index];
                                                                 
  if (instance->graph_instance != NULL)                          	
    doca_graph_instance_destroy(instance->graph_instance);                                                              	
  if (instance->source != NULL)                                  
    doca_buf_refcount_rm(instance->source, NULL);          	
  if (instance->dma_dest != NULL)                                	
    doca_buf_refcount_rm(instance->dma_dest, NULL);        
  if (instance->sha_dest != NULL)                                	
    doca_buf_refcount_rm(instance->sha_dest, NULL);        	
}                                                                      
                                                                       	
                                                                       	
/**                                                                    
 * Destroy instances                                                   	
 *                                                                     	
 * @state [in]: sample state                                           	
 */                                                                    	
void destroy_graph_instances(struct graph_sample_state *state) {       
  uint32_t i = 0;                                                      	
                                                                       	
  for (i = 0; i < NUM_GRAPH_INSTNACES; i++)                            	
    destroy_graph_instance(state, i);                                  	
}                                                                      
                                                                       	
/**                                                                    	
 * This method cleans up the sample resources in reverse order of their         creation.
 * This method does not check for destroy return values for simplify.  	
 * Real code should check the return value and act accordingly (e.g. if	 doca_workq_destroy failed it means that some
 * contexts are still added or even that there are still in flight jobs in the work queue).
 *
 * @state [in]: sample state
 */
void cleanup(struct graph_sample_state *state) {
  destroy_graph_instances(state);
  
  destroy_graph(state);
  
  stop_contexts(state);
  
  if (state->work_queue != NULL)
    doca_workq_destroy(state->work_queue);
  
  if (state->sha != NULL)
    doca_sha_destroy(state->sha);
  
  if (state->dma != NULL)
    doca_dma_destroy(state->dma);
  
  if (state->inventory != NULL) {
    doca_buf_inventory_stop(state->inventory);
    doca_buf_inventory_destroy(state->inventory);
  }
  
  if (state->mmap != NULL) {
    doca_mmap_stop(state->mmap);
    doca_mmap_destroy(state->mmap);
  }
  
  if (state->device != NULL)
    doca_dev_close(state->device);
  
  if (state->buffer != NULL)
    free(state->buffer);
}


/**
 * This method creates a SHA instance
 *
 * @state [in]: sample state
 * @index [in]: the SHA instance index
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_instance_sha(struct graph_sample_state *state, uint32_t index){
  struct graph_instance_data *instance = &state->instances[index];
  
  instance->index = index;
  
  /* Use doca_buf_inventory_buf_by_data to initialize the source buffer */
  EXIT_ON_FAILURE(doca_buf_inventory_buf_by_data(state->inventory, state->mmap, state->available_buffer,
  					       SOURCE_BUFFER_SIZE, &instance->source));
  memset(state->available_buffer, (index + 1), SOURCE_BUFFER_SIZE);
  instance->source_addr = state->available_buffer;
  state->available_buffer += SOURCE_BUFFER_SIZE;
  
  /* Initialize SHA job*/
  EXIT_ON_FAILURE(doca_buf_inventory_buf_by_addr(state->inventory, state->mmap, state->available_buffer,
  					       SHA_DEST_BUFFER_SIZE, &instance->sha_dest));
  instance->sha_dest_addr = state->available_buffer;
  state->available_buffer += SHA_DEST_BUFFER_SIZE;
  
  instance->sha_job.base.ctx = state->contexts[SAMPLE_CONTEXT_SHA];
  instance->sha_job.base.type = DOCA_SHA_JOB_SHA256;
  instance->sha_job.base.flags = DOCA_JOB_FLAGS_NONE;
  instance->sha_job.base.user_data.ptr = NULL;
  instance->sha_job.req_buf = instance->source;
  instance->sha_job.resp_buf = instance->sha_dest;
  
  return DOCA_SUCCESS;
}

/**
 * This method creates a DMA instance
 *
 * @state [in]: sample state
 * @index [in]: the DMA instance index
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_instance_dma(struct graph_sample_state *state, uint32_t index){
  struct graph_instance_data *instance = &state->instances[index];
  
  instance->index = index;
  
  /* Use doca_buf_inventory_buf_by_data to initialize the source buffer */
  EXIT_ON_FAILURE(doca_buf_inventory_buf_by_data(state->inventory, state->mmap, state->available_buffer,
  					       SOURCE_BUFFER_SIZE, &instance->source));
  memset(state->available_buffer, (index + 1), SOURCE_BUFFER_SIZE);
  instance->source_addr = state->available_buffer;
  state->available_buffer += SOURCE_BUFFER_SIZE;
  
  /* Initialize DMA job */
  EXIT_ON_FAILURE(doca_buf_inventory_buf_by_addr(state->inventory, state->mmap, state->available_buffer,
					       DMA_DEST_BUFFER_SIZE, &instance->dma_dest));
  instance->dma_dest_addr = state->available_buffer;
  state->available_buffer += DMA_DEST_BUFFER_SIZE;

  instance->dma_job.base.ctx = state->contexts[SAMPLE_CONTEXT_DMA];
  instance->dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
  instance->dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
  instance->dma_job.base.user_data.ptr = NULL;
  instance->dma_job.src_buff = instance->source;
  instance->dma_job.dst_buff = instance->dma_dest;
  
  return DOCA_SUCCESS;
}

/**
 * Create SHA instances
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_instances_sha(struct graph_sample_state *state) {
  uint32_t i = 0;
  
  for (i = 0; i < NUM_GRAPH_INSTNACES; i++)
    EXIT_ON_FAILURE(create_instance_sha(state, i));
  
  return DOCA_SUCCESS;
}

/**
 * Create DMA instances
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_instances_dma(struct graph_sample_state *state) {
  uint32_t i = 0;
  
  for (i = 0; i < NUM_GRAPH_INSTNACES; i++)
    EXIT_ON_FAILURE(create_instance_dma(state, i));
  
  return DOCA_SUCCESS;
}

/**
 * Submit SHA instances
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t submit_instances_sha(struct graph_sample_state *state){
  DOCA_LOG_INFO("Submitting SHA instances");
  uint32_t i = 0;
  
  for (i = 0; i < NUM_GRAPH_INSTNACES; i++) {
    
    EXIT_ON_FAILURE(doca_workq_submit(state->work_queue, &(state->instances[i].sha_job.base)));
  }
  
  return DOCA_SUCCESS;
}

/**
 * Submit DMA instances
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t submit_instances_dma(struct graph_sample_state *state){
  DOCA_LOG_INFO("Submitting DMA instances");
  uint32_t i = 0;
  
  for (i = 0; i < NUM_GRAPH_INSTNACES; i++) {
    
    EXIT_ON_FAILURE(doca_workq_submit(state->work_queue, &(state->instances[i].dma_job.base)));
  }
  
  return DOCA_SUCCESS;
}

/**
 * Poll the work queue until all SHA instances are completed
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t poll_for_completion_sha(struct graph_sample_state *state){
  DOCA_LOG_INFO("Polling SHA");

  uint32_t num_completed_instances = 0;
  doca_error_t status = DOCA_SUCCESS;
  
  while (num_completed_instances < NUM_GRAPH_INSTNACES) {
    struct doca_event ev = {0};
    struct graph_instance_data *instance = NULL;
    
    while ((status = doca_workq_progress_retrieve(state->work_queue, &ev,
    					      DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) == DOCA_ERROR_AGAIN) {
    	/* Sleep here. Notice that again is expected for intermediate graph jobs */
    }
    if (status != DOCA_SUCCESS) {
    	DOCA_LOG_ERR("Progress retrieve failed with status %s", doca_get_error_string(status));
    	return status;
    }
    
    num_completed_instances++;
  }
  
  DOCA_LOG_INFO("All SHA instances completed successfully");
  
  char sha_output[DOCA_SHA256_BYTE_COUNT * 2 + 1] = {0};
  for (int i = 0; i < DOCA_SHA256_BYTE_COUNT; i++)
    snprintf(sha_output + (2 * i), 3, "%02x", state->instances[0].sha_dest_addr[i]);

  DOCA_LOG_INFO("SHA Value: %s", sha_output);
  
  return DOCA_SUCCESS;
}

/**
 * Poll the work queue until all DMA instances are completed
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t poll_for_completion_dma(struct graph_sample_state *state){
  DOCA_LOG_INFO("Polling DMA");

  uint32_t num_completed_instances = 0;
  doca_error_t status = DOCA_SUCCESS;
  
  while (num_completed_instances < NUM_GRAPH_INSTNACES) {
    struct doca_event ev = {0};
    struct graph_instance_data *instance = NULL;
    
    while ((status = doca_workq_progress_retrieve(state->work_queue, &ev,
    					      DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) == DOCA_ERROR_AGAIN) {
    	/* Sleep here. Notice that again is expected for intermediate graph jobs */
    }
    if (status != DOCA_SUCCESS) {
    	DOCA_LOG_ERR("Progress retrieve failed with status %s", doca_get_error_string(status));
    	return status;
    }
    
    num_completed_instances++;
  }
  
  DOCA_LOG_INFO("All DMA instances completed successfully");
  
  size_t dma_length = 0;

  EXIT_ON_FAILURE(doca_buf_get_data_len(state->instances[0].dma_dest, &dma_length));
  
  if (dma_length != DMA_DEST_BUFFER_SIZE) {
    DOCA_LOG_ERR("DMA destination buffer length %zu should be %d", dma_length, DMA_DEST_BUFFER_SIZE);
    return DOCA_ERROR_BAD_STATE;
  }
  
  if (memcmp(state->instances[0].dma_dest_addr, state->instances[0].source_addr, dma_length) != 0) {
    DOCA_LOG_ERR("DMA source and destination mismatch");
    return DOCA_ERROR_BAD_STATE;
  }
  
  return DOCA_SUCCESS;
}

/**
 * Start SHA contexts
 * The method adds the device to the contexts, starts them and add them to the work queue.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t start_contexts_sha(struct graph_sample_state *state) {
  uint32_t i = 0;
  
  DOCA_LOG_INFO("Starting SHA contexts");
  
  for (i = 0; i < 1; i++) {
    EXIT_ON_FAILURE(doca_ctx_dev_add(state->contexts[i], state->device));
    EXIT_ON_FAILURE(doca_ctx_start(state->contexts[i]));
    EXIT_ON_FAILURE(doca_ctx_workq_add(state->contexts[i], state->work_queue));
  }
  
  return DOCA_SUCCESS;
}

/**
 * Start DMA contexts
 * The method adds the device to the contexts, starts them and add them to the work queue.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t start_contexts_dma(struct graph_sample_state *state) {
  uint32_t i = 0;
  
  DOCA_LOG_INFO("Starting DMA contexts");
  
  for (i = 1; i < 2; i++) {
    EXIT_ON_FAILURE(doca_ctx_dev_add(state->contexts[i], state->device));
    EXIT_ON_FAILURE(doca_ctx_start(state->contexts[i]));
    EXIT_ON_FAILURE(doca_ctx_workq_add(state->contexts[i], state->work_queue));
  }
  
  return DOCA_SUCCESS;
}

/**
 * Allocates a buffer that will be used for the source and destination buffers.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void allocate_buffer(struct graph_sample_state *state) {
  DOCA_LOG_INFO("Allocating buffer");

  state->buffer = (uint8_t *)malloc(BUFFER_SIZE);
  if (state->buffer == NULL)
    return;

  state->available_buffer = state->buffer;
}

/*
 * Check if DOCA device is SHA capable
 *
 * @devinfo [in]: Device to check
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t check_dev_sha_capable(struct doca_devinfo *devinfo) {
  doca_error_t status = doca_sha_job_get_supported(devinfo, DOCA_SHA_JOB_SHA256);
  
  if (status != DOCA_SUCCESS)
  	return status;
  
  return DOCA_SUCCESS;
}

/*
 * Check if DOCA device is DMA capable
 *
 * @devinfo [in]: Device to check
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t check_dev_dma_capable(struct doca_devinfo *devinfo) {
  
  doca_error_t status = doca_dma_job_get_supported(devinfo, DOCA_DMA_JOB_MEMCPY);
  if (status != DOCA_SUCCESS)
  	return status;
  
  return DOCA_SUCCESS;
}

/**
 * Opens a device that supports SHA
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void open_device_sha(struct graph_sample_state *state) {
  DOCA_LOG_INFO("Opening device");

  open_doca_device_with_capabilities(check_dev_sha_capable, &state->device);
}

/**
 * Opens a device that supports DMA
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void open_device_dma(struct graph_sample_state *state) {
  DOCA_LOG_INFO("Opening device");

  open_doca_device_with_capabilities(check_dev_dma_capable, &state->device);
}

/**
 * Create MMAP, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void create_mmap(struct graph_sample_state *state) {
  DOCA_LOG_INFO("Creating MMAP");

  doca_mmap_create(NULL, &state->mmap);
  doca_mmap_set_memrange(state->mmap, state->buffer, BUFFER_SIZE);
  doca_mmap_dev_add(state->mmap, state->device);
  doca_mmap_set_permissions(state->mmap, DOCA_ACCESS_LOCAL_READ_WRITE);
  doca_mmap_start(state->mmap);
}

	
/**
 * Create buffer inventory, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void create_buf_inventory(struct graph_sample_state *state){
  DOCA_LOG_INFO("Creating buf inventory");

  doca_buf_inventory_create(NULL, BUF_INVENTORY_SIZE, DOCA_BUF_EXTENSION_NONE, &state->inventory);
  doca_buf_inventory_start(state->inventory);
}

/**
 * Creates a work queue
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void create_work_queue(struct graph_sample_state *state) {
  DOCA_LOG_INFO("Creating work queue");

  doca_workq_create(WORK_QUEUE_DEPTH, &state->work_queue);
  doca_workq_set_event_driven_enable(state->work_queue, false);
}

/**
 * Create SHA
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void create_sha(struct graph_sample_state *state) {
  DOCA_LOG_INFO("Creating SHA");

  doca_sha_create(&state->sha);
  state->contexts[SAMPLE_CONTEXT_SHA] = doca_sha_as_ctx(state->sha);
}

/**
 * Run the SHA task
 *
 */
void* run_sha() {
  struct graph_sample_state state = {0}; 

  DOCA_LOG_INFO("START SHA task");
  allocate_buffer(&state);
  open_device_sha(&state);
  create_mmap(&state);
  create_buf_inventory(&state);
  create_work_queue(&state);
  create_sha(&state);
  start_contexts_sha(&state);
  create_instances_sha(&state);
  submit_instances_sha(&state);
  poll_for_completion_sha(&state);
}


/**
 * Create DMA
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
void create_dma(struct graph_sample_state *state) {
  DOCA_LOG_INFO("Creating DMA");

  doca_dma_create(&state->dma);
  state->contexts[SAMPLE_CONTEXT_DMA] = doca_dma_as_ctx(state->dma);
}

/**
 * Run the DMA task
 *
 */
void* run_dma() {
  struct graph_sample_state state = {0}; 

  DOCA_LOG_INFO("START DMA task");

  allocate_buffer(&state);
  open_device_dma(&state);
  create_mmap(&state);
  create_buf_inventory(&state);
  create_work_queue(&state);
  create_dma(&state);
  start_contexts_dma(&state);
  create_instances_dma(&state);
  submit_instances_dma(&state);
  poll_for_completion_dma(&state);

}

int main(int argc, char* argv[]) {

  long iterations = strtol(argv[1], NULL, 10);	
  
  doca_error_t result;
  int exit_status = EXIT_FAILURE;

  result = doca_log_create_standard_backend();

  DOCA_LOG_INFO("Starting the sample");
  
  pthread_t thread_sha, thread_dma; 

  for (int iteration = 0; iteration < iterations; ++iteration) {
    pthread_create(&thread_sha, NULL, run_sha, NULL); 
    pthread_create(&thread_dma, NULL, run_dma, NULL); 
    
    pthread_join(thread_sha, NULL);
    pthread_join(thread_dma, NULL);
  }

  return 0;
}
