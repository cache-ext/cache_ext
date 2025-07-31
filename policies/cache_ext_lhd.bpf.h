#ifndef _CACHE_EXT_LHD_BPF_H
#define _CACHE_EXT_LHD_BPF_H

#define HIT_AGE_CLASSES 16
#define APP_CLASSES 16
#define NUM_CLASSES ((HIT_AGE_CLASSES) * (APP_CLASSES))  // Must be power of two for masking
#define NUM_CLASSES_MASK (NUM_CLASSES - 1)
#define INITIAL_AGE_COARSENING_SHIFT 10
#define REQS_PER_RECONFIG (1 << 20)
#define MAX_AGE (1 << 14)  // Must be power of two for masking
#define MAX_AGE_MASK (MAX_AGE - 1)
#define DEFAULT_APP_ID 1  // TODO: can prob delete app stuff
#define RECENTLY_ADMITTED_SIZE 8

#define HIT_SCALING_FACTOR (1 << 20)
#define HIT_DENSITY_SCALING_FACTOR (1 << 20)
#define NUM_OBJECTS_SCALING_FACTOR (1 << 20)

#define TOTAL_EVENTS_THRESH (HIT_SCALING_FACTOR / 100000)
#define AGE_COARSENING_ERROR_TOLERANCE 100 // Inverse of value in libcachesim

#endif /* _CACHE_EXT_LHD_BPF_H */
