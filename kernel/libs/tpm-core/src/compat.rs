// SPDX-License-Identifier: MPL-2.0

pub(crate) fn array_as_slice<T, const N: usize>(array: &[T; N]) -> &[T] {
    array
}

pub(crate) fn array_index_get<T, const N: usize>(array: &[T; N], index: usize) -> &T {
    &array[index]
}

pub(crate) fn slice_index_get<T>(slice: &[T], index: usize) -> &T {
    &slice[index]
}

pub(crate) fn slice_subrange<T>(slice: &[T], start: usize, end: usize) -> &[T] {
    &slice[start..end]
}
