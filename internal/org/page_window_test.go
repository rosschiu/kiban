package org

import "testing"

func TestPageWindow(t *testing.T) {
	cases := []struct {
		page, pageSize     int
		wantLimit, wantOff int32
	}{
		{0, 0, 25, 0},
		{1, 10, 10, 0},
		{3, 10, 10, 20},
		{maxPage + 1, maxPageSize + 1, maxPageSize, int32((maxPage - 1) * maxPageSize)},
		{1 << 40, 1 << 40, maxPageSize, int32((maxPage - 1) * maxPageSize)},
	}
	for _, c := range cases {
		limit, offset := pageWindow(c.page, c.pageSize)
		if limit != c.wantLimit || offset != c.wantOff {
			t.Errorf("pageWindow(%d, %d) = %d, %d; want %d, %d", c.page, c.pageSize, limit, offset, c.wantLimit, c.wantOff)
		}
	}
}
