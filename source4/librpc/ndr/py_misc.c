/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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
#include "librpc/gen_ndr/misc.h"

#if PY_MAJOR_VERSION >= 3
#define PyStr_Check PyUnicode_Check
#define PyStr_FromString PyUnicode_FromString
#define PyStr_FromFormat PyUnicode_FromFormat
#define PyStr_AsString PyUnicode_AsUTF8
#else
#define PyStr_Check PyString_Check
#define PyStr_FromString PyString_FromString
#define PyStr_FromFormat PyString_FromFormat
#define PyStr_AsString PyString_AsString
#endif

static int py_GUID_cmp(PyObject *py_self, PyObject *py_other)
{
	int ret;
	struct GUID *self = pytalloc_get_ptr(py_self), *other;
	other = pytalloc_get_ptr(py_other);
	if (other == NULL)
		return -1;

	ret = GUID_compare(self, other);
	if (ret < 0) {
		return -1;
	} else if (ret > 0) {
		return 1;
	} else {
		return 0;
	}
}

static PyObject* py_GUID_richcmp(PyObject *obj1, PyObject *obj2, int op)
{
	int result = py_GUID_cmp(obj1, obj2);
	
	switch (op) {
		case Py_EQ: return PyBool_FromLong(result == 0);
		case Py_NE: return PyBool_FromLong(result != 0);
		case Py_LT: return PyBool_FromLong(result < 0);
		case Py_GT: return PyBool_FromLong(result > 0);
		case Py_LE: return PyBool_FromLong(result <= 0);
		case Py_GE: return PyBool_FromLong(result >= 0);
	}
	Py_INCREF(Py_NotImplemented);
	return Py_NotImplemented;
}

static PyObject *py_GUID_str(PyObject *py_self)
{
	struct GUID *self = pytalloc_get_ptr(py_self);
	char *str = GUID_string(NULL, self);
	PyObject *ret = PyStr_FromString(str);
	talloc_free(str);
	return ret;
}

static PyObject *py_GUID_repr(PyObject *py_self)
{
	struct GUID *self = pytalloc_get_ptr(py_self);
	char *str = GUID_string(NULL, self);
	PyObject *ret = PyStr_FromFormat("GUID('%s')", str);
	talloc_free(str);
	return ret;
}

static int py_GUID_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *str = NULL;
	NTSTATUS status;
	struct GUID *guid = pytalloc_get_ptr(self);
	const char *kwnames[] = { "str", NULL };
#if PY_MAJOR_VERSION >= 3
	Py_ssize_t size;
#endif

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O", discard_const_p(char *, kwnames), &str))
		return -1;

	if (str != NULL) {
		DATA_BLOB guid_val;

		if (!PyStr_Check(str)) {
			PyErr_SetString(PyExc_TypeError, "Expected a string argument to GUID()");
			return -1;
		}
#if PY_MAJOR_VERSION >= 3
		guid_val.data = (uint8_t *)PyUnicode_AsUTF8AndSize(str, &size);
		guid_val.length = size;
#else
		guid_val.data = (uint8_t *)PyString_AsString(str);
		guid_val.length = PyString_Size(str);
#endif
		status = GUID_from_data_blob(&guid_val, guid);
		if (!NT_STATUS_IS_OK(status)) {
			PyErr_SetNTSTATUS(status);
			return -1;
		}
	}

	return 0;
}

static void py_GUID_patch(PyTypeObject *type)
{
	type->tp_init = py_GUID_init;
	type->tp_str = py_GUID_str;
	type->tp_repr = py_GUID_repr;
	type->tp_richcompare = py_GUID_richcmp;
#if PY_MAJOR_VERSION < 3
	type->tp_compare = py_GUID_cmp;
#endif
}

#define PY_GUID_PATCH py_GUID_patch

static int py_policy_handle_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *str = NULL;
	NTSTATUS status;
	struct policy_handle *handle = pytalloc_get_ptr(self);
	const char *kwnames[] = { "uuid", "type", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|si", discard_const_p(char *, kwnames), &str, &handle->handle_type))
		return -1;

	if (str != NULL) {
		status = GUID_from_string(str, &handle->uuid);
		if (!NT_STATUS_IS_OK(status)) {
			PyErr_SetNTSTATUS(status);
			return -1;
		}
	}

	return 0;
}

static PyObject *py_policy_handle_repr(PyObject *py_self)
{
	struct policy_handle *self = pytalloc_get_ptr(py_self);
	char *uuid_str = GUID_string(NULL, &self->uuid);
	PyObject *ret = PyStr_FromFormat("policy_handle(%d, '%s')", self->handle_type, uuid_str);
	talloc_free(uuid_str);
	return ret;
}

static PyObject *py_policy_handle_str(PyObject *py_self)
{
	struct policy_handle *self = pytalloc_get_ptr(py_self);
	char *uuid_str = GUID_string(NULL, &self->uuid);
	PyObject *ret = PyStr_FromFormat("%d, %s", self->handle_type, uuid_str);
	talloc_free(uuid_str);
	return ret;
}

static void py_policy_handle_patch(PyTypeObject *type)
{
	type->tp_init = py_policy_handle_init;
	type->tp_repr = py_policy_handle_repr;
	type->tp_str = py_policy_handle_str;
}

#define PY_POLICY_HANDLE_PATCH py_policy_handle_patch

