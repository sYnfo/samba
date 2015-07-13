/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Amitay Isaacs <amitay@gmail.com> 2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include "includes.h"
#include "param/param.h"
#include "param/loadparm.h"
#include "lib/talloc/pytalloc.h"

static PyTypeObject *loadparm_Type = NULL;

static PyObject *py_get_context(PyObject *self)
{
	PyObject *py_loadparm;
	const struct loadparm_s3_helpers *s3_context;
	const struct loadparm_context *s4_context;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	s3_context = loadparm_s3_helpers();

	s4_context = loadparm_init_s3(mem_ctx, s3_context);
	if (s4_context == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	py_loadparm = pytalloc_steal(loadparm_Type, discard_const_p(struct loadparm_context, s4_context));
	if (py_loadparm == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	talloc_free(mem_ctx);

	return py_loadparm;
}

static PyMethodDef pyparam_methods[] = {
    { "get_context", (PyCFunction)py_get_context, METH_NOARGS,
        "Returns LoadParm context." },
    { NULL }
};

#define MODULE_DOC "Parsing and writing Samba3 configuration files."

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "param",
	.m_doc = MODULE_DOC,
	.m_size = -1,
	.m_methods = pyparam_methods,
};
#endif

static PyObject* module_init(void)
{
	PyObject *m, *mod;

#if PY_MAJOR_VERSION >= 3
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule3("param", pyparam_methods, MODULE_DOC);
#endif
	if (m == NULL)
		return NULL;

	mod = PyImport_ImportModule("samba.param");
	if (mod == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	loadparm_Type = (PyTypeObject *)PyObject_GetAttrString(mod, "LoadParm");
	Py_DECREF(mod);
	if (loadparm_Type == NULL) {
		Py_DECREF(m);
		return NULL;
	}
	return m;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_param(void);
PyMODINIT_FUNC PyInit_param(void)
{
    return module_init();
}
#else
void initparam(void);
void initparam(void)
{
    module_init();
}
#endif
