/**
 * @file microvm_python.c
 * @brief Python bindings for the MicroVM library
 * 
 * This module provides Python bindings for the MicroVM library,
 * allowing Python applications to create secure execution environments.
 * 
 * Usage:
 *     import microvm
 *     
 *     vm = microvm.create(mode='user', network='tcp', gpu='disabled')
 *     vm.load(bytecode)
 *     vm.run()
 *     print(vm.get_exit_code())
 */

#include <Python.h>
#include <structmember.h>
#include "microvm.h"

/* Forward declarations for renamed functions */
static PyObject *py_microvm_create(PyTypeObject *type, PyObject *args, PyObject *kwds);
static PyObject *py_microvm_load(PyObject *self, PyObject *args);
static PyObject *py_microvm_run(PyObject *self, PyObject *args);
static PyObject *py_microvm_stop(PyObject *self, PyObject *args);
static PyObject *py_microvm_get_exit_code(PyObject *self, PyObject *args);
static PyObject *py_microvm_get_state(PyObject *self, PyObject *args);
static PyObject *py_microvm_get_cycles(PyObject *self, PyObject *args);
static PyObject *py_microvm_set_mode(PyObject *self, PyObject *args);
static PyObject *py_microvm_compile(PyObject *self, PyObject *args);

typedef struct {
    PyObject_HEAD
    microvm_t *vm;
    PyObject *on_output;
    PyObject *on_error;
} MicroVMObject;

static int microvm_traverse(PyObject *self, visitproc visit, void *arg) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    if (vm_obj->on_output) {
        Py_VISIT(vm_obj->on_output);
    }
    if (vm_obj->on_error) {
        Py_VISIT(vm_obj->on_error);
    }
    return 0;
}

static int microvm_clear(PyObject *self) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    Py_CLEAR(vm_obj->on_output);
    Py_CLEAR(vm_obj->on_error);
    return 0;
}

static void microvm_dealloc(PyObject *self) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    if (vm_obj->vm) {
        microvm_destroy(vm_obj->vm);
    }
    microvm_clear(self);
    Py_TYPE(self)->tp_free(self);
}

/* Module methods */
static PyMethodDef MicroVMMethods[] = {
    {"load", py_microvm_load, METH_VARARGS, "Load bytecode into VM"},
    {"run", py_microvm_run, METH_NOARGS, "Execute bytecode"},
    {"stop", py_microvm_stop, METH_NOARGS, "Stop execution"},
    {"get_exit_code", py_microvm_get_exit_code, METH_NOARGS, "Get exit code"},
    {"get_state", py_microvm_get_state, METH_NOARGS, "Get VM state"},
    {"get_cycles", py_microvm_get_cycles, METH_NOARGS, "Get cycle count"},
    {"set_mode", py_microvm_set_mode, METH_VARARGS, "Set execution mode"},
    {"compile", py_microvm_compile, METH_VARARGS, "Compile source to bytecode"},
    {NULL, NULL, 0, NULL}
};

/* Type definition */
static PyTypeObject MicroVMType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "microvm.MicroVM",
    .tp_doc = "MicroVM - Secure Execution Environment",
    .tp_basicsize = sizeof(MicroVMObject),
    .tp_itemsize = 0,
    .tp_dealloc = microvm_dealloc,
    .tp_traverse = microvm_traverse,
    .tp_clear = microvm_clear,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = py_microvm_create,
    .tp_methods = MicroVMMethods,
};

/* Implementation of methods */

static PyObject *py_microvm_create(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    MicroVMObject *self;
    self = (MicroVMObject *)type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }
    
    self->vm = NULL;
    self->on_output = NULL;
    self->on_error = NULL;
    
    /* Parse arguments */
    char *mode_str = "user";
    char *network_str = "all";
    char *gpu_str = "disabled";
    
    static char *kwlist[] = {"mode", "network", "gpu", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "sss", kwlist, 
                                     &mode_str, &network_str, &gpu_str)) {
        return NULL;
    }
    
    /* Convert mode string to enum */
    microvm_mode_t mode = MICROVM_MODE_USER;
    if (strcmp(mode_str, "kernel") == 0) mode = MICROVM_MODE_KERNEL;
    else if (strcmp(mode_str, "sandbox") == 0) mode = MICROVM_MODE_SANDBOX;
    
    /* Convert network string to enum */
    microvm_network_mode_t network = MICROVM_NET_ALL;
    if (strcmp(network_str, "disabled") == 0) network = MICROVM_NET_DISABLED;
    else if (strcmp(network_str, "tcp") == 0) network = MICROVM_NET_TCP;
    else if (strcmp(network_str, "udp") == 0) network = MICROVM_NET_UDP;
    
    /* Convert GPU string to enum */
    microvm_gpu_mode_t gpu = MICROVM_GPU_DISABLED;
    if (strcmp(gpu_str, "nvidia") == 0) gpu = MICROVM_GPU_NVIDIA;
    else if (strcmp(gpu_str, "amd") == 0) gpu = MICROVM_GPU_AMD;
    else if (strcmp(gpu_str, "metal") == 0) gpu = MICROVM_GPU_METAL;
    else if (strcmp(gpu_str, "all") == 0) gpu = MICROVM_GPU_ALL;
    
    /* Create configuration */
    microvm_config_t config = {
        .mode = mode,
        .network_mode = network,
        .gpu_mode = gpu,
        .memory_size = MICROVM_MAX_MEMORY,
        .stack_size = MICROVM_MAX_STACK_SIZE,
        .debug_enabled = false,
    };
    
    /* Initialize library if needed */
    microvm_init();
    
    /* Create VM */
    self->vm = microvm_create(&config);
    if (!self->vm) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to create VM");
        return NULL;
    }
    
    return (PyObject *)self;
}

static PyObject *py_microvm_load(PyObject *self, PyObject *args) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    
    Py_buffer bytecode;
    if (!PyArg_ParseTuple(args, "y*", &bytecode)) {
        return NULL;
    }
    
    if (!vm_obj->vm) {
        PyBuffer_Release(&bytecode);
        PyErr_SetString(PyExc_RuntimeError, "VM not initialized");
        return NULL;
    }
    
    microvm_error_t err = microvm_load(vm_obj->vm, bytecode.buf, bytecode.len);
    PyBuffer_Release(&bytecode);
    
    if (err != MICROVM_SUCCESS) {
        PyErr_SetString(PyExc_RuntimeError, microvm_get_error(vm_obj->vm));
        return NULL;
    }
    
    Py_RETURN_TRUE;
}

static PyObject *py_microvm_run(PyObject *self, PyObject *args) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    
    if (!vm_obj->vm) {
        PyErr_SetString(PyExc_RuntimeError, "VM not initialized");
        return NULL;
    }
    
    microvm_error_t err = microvm_run(vm_obj->vm);
    
    if (err != MICROVM_SUCCESS) {
        PyErr_SetString(PyExc_RuntimeError, microvm_get_error(vm_obj->vm));
        return NULL;
    }
    
    return PyLong_FromLong(microvm_get_exit_code(vm_obj->vm));
}

static PyObject *py_microvm_stop(PyObject *self, PyObject *args) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    
    if (!vm_obj->vm) {
        PyErr_SetString(PyExc_RuntimeError, "VM not initialized");
        return NULL;
    }
    
    microvm_stop(vm_obj->vm);
    Py_RETURN_NONE;
}

static PyObject *py_microvm_get_exit_code(PyObject *self, PyObject *args) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    
    if (!vm_obj->vm) {
        return PyLong_FromLong(-1);
    }
    
    return PyLong_FromLong(microvm_get_exit_code(vm_obj->vm));
}

static PyObject *py_microvm_get_state(PyObject *self, PyObject *args) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    
    if (!vm_obj->vm) {
        return PyUnicode_FromString("Not initialized");
    }
    
    return PyUnicode_FromString(microvm_state_to_string(vm_obj->vm));
}

static PyObject *py_microvm_get_cycles(PyObject *self, PyObject *args) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    
    if (!vm_obj->vm) {
        return PyLong_FromLong(0);
    }
    
    return PyLong_FromUnsignedLongLong(microvm_get_cycles(vm_obj->vm));
}

static PyObject *py_microvm_set_mode(PyObject *self, PyObject *args) {
    MicroVMObject *vm_obj = (MicroVMObject *)self;
    
    char *mode_str;
    if (!PyArg_ParseTuple(args, "s", &mode_str)) {
        return NULL;
    }
    
    microvm_mode_t mode = MICROVM_MODE_USER;
    if (strcmp(mode_str, "kernel") == 0) mode = MICROVM_MODE_KERNEL;
    else if (strcmp(mode_str, "sandbox") == 0) mode = MICROVM_MODE_SANDBOX;
    
    microvm_set_mode(vm_obj->vm, mode);
    Py_RETURN_NONE;
}

static PyObject *py_microvm_compile(PyObject *self, PyObject *args) {
    /* Placeholder for bytecode compiler */
    PyErr_SetString(PyExc_NotImplementedError, "Compiler not yet implemented");
    return NULL;
}

/* Module definition */
static struct PyModuleDef microvmmodule = {
    PyModuleDef_HEAD_INIT,
    "microvm",
    "BigWeiner MicroVM - Secure Python module execution",
    -1,
    NULL
};

PyMODINIT_FUNC PyInit_microvm(void) {
    PyObject *module;
    
    module = PyModule_Create(&microvmmodule);
    if (module == NULL) {
        return NULL;
    }
    
    if (PyType_Ready(&MicroVMType) < 0) {
        return NULL;
    }
    
    Py_INCREF(&MicroVMType);
    if (PyModule_AddObject(module, "MicroVM", (PyObject *)&MicroVMType) < 0) {
        Py_DECREF(&MicroVMType);
        Py_DECREF(module);
        return NULL;
    }
    
    /* Add constants */
    PyModule_AddStringConstant(module, "__version__", MICROVM_VERSION_STRING);
    PyModule_AddIntConstant(module, "MODE_KERNEL", MICROVM_MODE_KERNEL);
    PyModule_AddIntConstant(module, "MODE_USER", MICROVM_MODE_USER);
    PyModule_AddIntConstant(module, "MODE_SANDBOX", MICROVM_MODE_SANDBOX);
    
    PyModule_AddIntConstant(module, "NET_DISABLED", MICROVM_NET_DISABLED);
    PyModule_AddIntConstant(module, "NET_TCP", MICROVM_NET_TCP);
    PyModule_AddIntConstant(module, "NET_UDP", MICROVM_NET_UDP);
    PyModule_AddIntConstant(module, "NET_ALL", MICROVM_NET_ALL);
    
    PyModule_AddIntConstant(module, "GPU_DISABLED", MICROVM_GPU_DISABLED);
    PyModule_AddIntConstant(module, "GPU_NVIDIA", MICROVM_GPU_NVIDIA);
    PyModule_AddIntConstant(module, "GPU_AMD", MICROVM_GPU_AMD);
    PyModule_AddIntConstant(module, "GPU_METAL", MICROVM_GPU_METAL);
    PyModule_AddIntConstant(module, "GPU_ALL", MICROVM_GPU_ALL);
    
    return module;
}
