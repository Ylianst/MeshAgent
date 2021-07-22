/*
Copyright 2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

* @description Mini DHCP Client Module, to fetch configuration data
* @author Bryan Roe & Ylian Saint-Hilaire
*/

// DHCP Information
if (Function.prototype.internal == null) { Object.defineProperty(Function.prototype, 'internal', { get: function () { return (this); } }); }
if (global._hide == null)
{
    global._hide = function _hide(v)
    {
        if(v==null || (v!=null && typeof(v)=='boolean'))
        {
            var ret = _hide.currentObject;
            if (v) { _hide.currentObject = null; }
            return (ret);
        }
        else
        {
            _hide.currentObject = v;
        }
    }
}
addModule('promise2', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE4IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgcmVmVGFibGUgPSB7fTsNCg0KZnVuY3Rpb24gcHJvbWlzZUluaXRpYWxpemVyKHIsaikNCnsNCiAgICB0aGlzLl9yZXMgPSByOw0KICAgIHRoaXMuX3JlaiA9IGo7DQp9DQoNCmZ1bmN0aW9uIGdldFJvb3RQcm9taXNlKG9iaikNCnsNCiAgICB3aGlsZShvYmoucGFyZW50UHJvbWlzZSkNCiAgICB7DQogICAgICAgIG9iaiA9IG9iai5wYXJlbnRQcm9taXNlOw0KICAgIH0NCiAgICByZXR1cm4gKG9iaik7DQp9DQoNCmZ1bmN0aW9uIGV2ZW50X3N3aXRjaGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQpDQp7DQogICAgcmV0dXJuICh7IF9PYmplY3RJRDogJ2V2ZW50X3N3aXRjaGVyJywgZnVuYzogdGFyZ2V0LmJpbmQoZGVzaXJlZF9jYWxsZWUpIH0pOw0KfQ0KDQpmdW5jdGlvbiBldmVudF9mb3J3YXJkZXIoc291cmNlT2JqLCBzb3VyY2VOYW1lLCB0YXJnZXRPYmosIHRhcmdldE5hbWUpDQp7DQogICAgc291cmNlT2JqLm9uKHNvdXJjZU5hbWUsIHRhcmdldE9iai5lbWl0LmJpbmQodGFyZ2V0T2JqKSk7DQp9DQoNCg0KZnVuY3Rpb24gcmV0dXJuX3Jlc29sdmVkKCkNCnsNCiAgICB2YXIgcGFybXMgPSBbJ3Jlc29sdmVkJ107DQogICAgZm9yICh2YXIgYWkgaW4gYXJndW1lbnRzKQ0KICAgIHsNCiAgICAgICAgcGFybXMucHVzaChhcmd1bWVudHNbYWldKTsNCiAgICB9DQogICAgdGhpcy5fWFNMRi5lbWl0LmFwcGx5KHRoaXMuX1hTTEYsIHBhcm1zKTsNCn0NCmZ1bmN0aW9uIHJldHVybl9yZWplY3RlZCgpDQp7DQogICAgdGhpcy5fWFNMRi5wcm9taXNlLl9fY2hpbGRQcm9taXNlLl9yZWooZSk7DQp9DQpmdW5jdGlvbiBlbWl0cmVqZWN0KGEpDQp7DQogICAgcHJvY2Vzcy5lbWl0KCd1bmNhdWdodEV4Y2VwdGlvbicsICdwcm9taXNlLnVuY2F1Z2h0UmVqZWN0aW9uOiAnICsgSlNPTi5zdHJpbmdpZnkoYSkpOw0KfQ0KZnVuY3Rpb24gUHJvbWlzZShwcm9taXNlRnVuYykNCnsNCiAgICB0aGlzLl9PYmplY3RJRCA9ICdwcm9taXNlJzsNCiAgICB0aGlzLnByb21pc2UgPSB0aGlzOw0KICAgIHRoaXMuX2ludGVybmFsID0geyBfT2JqZWN0SUQ6ICdwcm9taXNlLmludGVybmFsJywgcHJvbWlzZTogdGhpcywgY29tcGxldGVkOiBmYWxzZSwgZXJyb3JzOiBmYWxzZSwgY29tcGxldGVkQXJnczogW10sIGludGVybmFsQ291bnQ6IDAsIF91cDogbnVsbCB9Ow0KICAgIHJlcXVpcmUoJ2V2ZW50cycpLkV2ZW50RW1pdHRlci5jYWxsKHRoaXMuX2ludGVybmFsKTsNCiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgInBhcmVudFByb21pc2UiLA0KICAgICAgICB7DQogICAgICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHsgcmV0dXJuICh0aGlzLl91cCk7IH0sDQogICAgICAgICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBpZiAodmFsdWUgIT0gbnVsbCAmJiB0aGlzLl91cCA9PSBudWxsKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgLy8gV2UgYXJlIG5vIGxvbmdlciBhbiBvcnBoYW4NCiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuX2ludGVybmFsLnVuY2F1Z2h0ICE9IG51bGwpDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFySW1tZWRpYXRlKHRoaXMuX2ludGVybmFsLnVuY2F1Z2h0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX2ludGVybmFsLnVuY2F1Z2h0ID0gbnVsbDsNCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB0aGlzLl91cCA9IHZhbHVlOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9KTsNCiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgImRlc2NyaXB0b3JNZXRhZGF0YSIsDQogICAgICAgIHsNCiAgICAgICAgICAgIGdldDogZnVuY3Rpb24gKCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXR1cm4gKHJlcXVpcmUoJ2V2ZW50cycpLmdldFByb3BlcnR5LmNhbGwodGhpcy5faW50ZXJuYWwsICc/X0ZpbmFsaXplckRlYnVnTWVzc2FnZScpKTsNCiAgICAgICAgICAgIH0sDQogICAgICAgICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXF1aXJlKCdldmVudHMnKS5zZXRQcm9wZXJ0eS5jYWxsKHRoaXMuX2ludGVybmFsLCAnP19GaW5hbGl6ZXJEZWJ1Z01lc3NhZ2UnLCB2YWx1ZSk7DQogICAgICAgICAgICB9DQogICAgICAgIH0pOw0KICAgIHRoaXMuX2ludGVybmFsLm9uKCd+JywgZnVuY3Rpb24gKCkNCiAgICB7DQogICAgICAgIHRoaXMuY29tcGxldGVkQXJncyA9IFtdOw0KICAgIH0pOw0KICAgIHRoaXMuX2ludGVybmFsLm9uKCduZXdMaXN0ZW5lcjInLCAoZnVuY3Rpb24gKGV2ZW50TmFtZSwgZXZlbnRDYWxsYmFjaykNCiAgICB7DQogICAgICAgIC8vY29uc29sZS5sb2coJ25ld0xpc3RlbmVyJywgZXZlbnROYW1lLCAnZXJyb3JzLycgKyB0aGlzLmVycm9ycyArICcgY29tcGxldGVkLycgKyB0aGlzLmNvbXBsZXRlZCk7DQogICAgICAgIHZhciByID0gbnVsbDsNCg0KICAgICAgICBpZiAoZXZlbnROYW1lID09ICdyZXNvbHZlZCcgJiYgIXRoaXMuZXJyb3JzICYmIHRoaXMuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICByID0gZXZlbnRDYWxsYmFjay5hcHBseSh0aGlzLCB0aGlzLmNvbXBsZXRlZEFyZ3MpOw0KICAgICAgICAgICAgaWYociE9bnVsbCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJywgcik7DQogICAgICAgICAgICB9DQogICAgICAgICAgICB0aGlzLnJlbW92ZUFsbExpc3RlbmVycygncmVzb2x2ZWQnKTsNCiAgICAgICAgICAgIHRoaXMucmVtb3ZlQWxsTGlzdGVuZXJzKCdyZWplY3RlZCcpOw0KICAgICAgICB9DQoNCiAgICAgICAgLy9pZiAoZXZlbnROYW1lID09ICdyZWplY3RlZCcgJiYgKGV2ZW50Q2FsbGJhY2suaW50ZXJuYWwgPT0gbnVsbCB8fCBldmVudENhbGxiYWNrLmludGVybmFsID09IGZhbHNlKSkNCiAgICAgICAgaWYgKGV2ZW50TmFtZSA9PSAncmVqZWN0ZWQnKQ0KICAgICAgICB7DQogICAgICAgICAgICB2YXIgcnAgPSBnZXRSb290UHJvbWlzZSh0aGlzLnByb21pc2UpOw0KICAgICAgICAgICAgcnAuX2ludGVybmFsLmV4dGVybmFsID0gdHJ1ZTsNCiAgICAgICAgICAgIGlmICh0aGlzLnVuY2F1Z2h0ICE9IG51bGwpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgY2xlYXJJbW1lZGlhdGUodGhpcy51bmNhdWdodCk7DQogICAgICAgICAgICAgICAgdGhpcy51bmNhdWdodCA9IG51bGw7DQogICAgICAgICAgICB9DQogICAgICAgICAgICBpZiAocnAuX2ludGVybmFsLnVuY2F1Z2h0ICE9IG51bGwpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgY2xlYXJJbW1lZGlhdGUocnAuX2ludGVybmFsLnVuY2F1Z2h0KTsNCiAgICAgICAgICAgICAgICBycC5faW50ZXJuYWwudW5jYXVnaHQgPSBudWxsOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQoNCiAgICAgICAgaWYgKGV2ZW50TmFtZSA9PSAncmVqZWN0ZWQnICYmIHRoaXMuZXJyb3JzICYmIHRoaXMuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICBldmVudENhbGxiYWNrLmFwcGx5KHRoaXMsIHRoaXMuY29tcGxldGVkQXJncyk7DQogICAgICAgICAgICB0aGlzLnJlbW92ZUFsbExpc3RlbmVycygncmVzb2x2ZWQnKTsNCiAgICAgICAgICAgIHRoaXMucmVtb3ZlQWxsTGlzdGVuZXJzKCdyZWplY3RlZCcpOw0KICAgICAgICB9DQogICAgICAgIGlmIChldmVudE5hbWUgPT0gJ3NldHRsZWQnICYmIHRoaXMuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICBldmVudENhbGxiYWNrLmFwcGx5KHRoaXMsIFtdKTsNCiAgICAgICAgfQ0KICAgIH0pLmludGVybmFsKTsNCiAgICB0aGlzLl9pbnRlcm5hbC5yZXNvbHZlciA9IGZ1bmN0aW9uIF9yZXNvbHZlcigpDQogICAgew0KICAgICAgICBpZiAodGhpcy5jb21wbGV0ZWQpIHsgcmV0dXJuOyB9DQogICAgICAgIHRoaXMuZXJyb3JzID0gZmFsc2U7DQogICAgICAgIHRoaXMuY29tcGxldGVkID0gdHJ1ZTsNCiAgICAgICAgdGhpcy5jb21wbGV0ZWRBcmdzID0gW107DQogICAgICAgIHZhciBhcmdzID0gWydyZXNvbHZlZCddOw0KICAgICAgICBpZiAodGhpcy5lbWl0X3JldHVyblZhbHVlICYmIHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKSAhPSBudWxsKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLmNvbXBsZXRlZEFyZ3MucHVzaCh0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJykpOw0KICAgICAgICAgICAgYXJncy5wdXNoKHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICBmb3IgKHZhciBhIGluIGFyZ3VtZW50cykNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLmNvbXBsZXRlZEFyZ3MucHVzaChhcmd1bWVudHNbYV0pOw0KICAgICAgICAgICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbYV0pOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgICAgIGlmIChhcmdzLmxlbmd0aCA9PSAyICYmIGFyZ3NbMV0hPW51bGwgJiYgdHlwZW9mKGFyZ3NbMV0pID09ICdvYmplY3QnICYmIGFyZ3NbMV0uX09iamVjdElEID09ICdwcm9taXNlJykNCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIHByID0gZ2V0Um9vdFByb21pc2UodGhpcy5wcm9taXNlKTsNCiAgICAgICAgICAgIGFyZ3NbMV0uX1hTTEYgPSB0aGlzOw0KICAgICAgICAgICAgYXJnc1sxXS50aGVuKHJldHVybl9yZXNvbHZlZCwgcmV0dXJuX3JlamVjdGVkKTsNCiAgICAgICAgfQ0KICAgICAgICBlbHNlDQogICAgICAgIHsNCiAgICAgICAgICAgIHRoaXMuZW1pdC5hcHBseSh0aGlzLCBhcmdzKTsNCiAgICAgICAgICAgIHRoaXMuZW1pdCgnc2V0dGxlZCcpOw0KICAgICAgICB9DQogICAgfTsNCg0KICAgIHRoaXMuX2ludGVybmFsLnJlamVjdG9yID0gZnVuY3Rpb24gX3JlamVjdG9yKCkNCiAgICB7DQogICAgICAgIGlmICh0aGlzLmNvbXBsZXRlZCkgeyByZXR1cm47IH0NCiAgICAgICAgdGhpcy5lcnJvcnMgPSB0cnVlOw0KICAgICAgICB0aGlzLmNvbXBsZXRlZCA9IHRydWU7DQogICAgICAgIHRoaXMuY29tcGxldGVkQXJncyA9IFtdOw0KICAgICAgICB2YXIgYXJncyA9IFsncmVqZWN0ZWQnXTsNCiAgICAgICAgZm9yICh2YXIgYSBpbiBhcmd1bWVudHMpDQogICAgICAgIHsNCiAgICAgICAgICAgIHRoaXMuY29tcGxldGVkQXJncy5wdXNoKGFyZ3VtZW50c1thXSk7DQogICAgICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2FdKTsNCiAgICAgICAgfQ0KDQogICAgICAgIHZhciByID0gZ2V0Um9vdFByb21pc2UodGhpcy5wcm9taXNlKTsNCiAgICAgICAgaWYgKChyLl9pbnRlcm5hbC5leHRlcm5hbCA9PSBudWxsIHx8IHIuX2ludGVybmFsLmV4dGVybmFsID09IGZhbHNlKSAmJiByLl9pbnRlcm5hbC51bmNhdWdodCA9PSBudWxsKQ0KICAgICAgICB7DQogICAgICAgICAgICByLl9pbnRlcm5hbC51bmNhdWdodCA9IHNldEltbWVkaWF0ZShlbWl0cmVqZWN0LCBhcmd1bWVudHNbMF0pOw0KICAgICAgICB9DQoNCiAgICAgICAgdGhpcy5lbWl0LmFwcGx5KHRoaXMsIGFyZ3MpOw0KICAgICAgICB0aGlzLmVtaXQoJ3NldHRsZWQnKTsNCiAgICB9Ow0KDQogICAgdGhpcy5jYXRjaCA9IGZ1bmN0aW9uKGZ1bmMpDQogICAgew0KICAgICAgICB2YXIgcnQgPSBnZXRSb290UHJvbWlzZSh0aGlzKTsNCiAgICAgICAgaWYgKHJ0Ll9pbnRlcm5hbC51bmNhdWdodCAhPSBudWxsKSB7IGNsZWFySW1tZWRpYXRlKHJ0Ll9pbnRlcm5hbC51bmNhdWdodCk7IH0NCiAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCBmdW5jKS5mdW5jLmludGVybmFsKTsNCiAgICB9DQogICAgdGhpcy5maW5hbGx5ID0gZnVuY3Rpb24gKGZ1bmMpDQogICAgew0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdzZXR0bGVkJywgZXZlbnRfc3dpdGNoZXIodGhpcywgZnVuYykuZnVuYy5pbnRlcm5hbCk7DQogICAgfTsNCiAgICB0aGlzLnRoZW4gPSBmdW5jdGlvbiAocmVzb2x2ZWQsIHJlamVjdGVkKQ0KICAgIHsNCiAgICAgICAgaWYgKHJlc29sdmVkKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZXNvbHZlZCcsIGV2ZW50X3N3aXRjaGVyKHRoaXMsIHJlc29sdmVkKS5mdW5jLmludGVybmFsKTsNCiAgICAgICAgfQ0KICAgICAgICBpZiAocmVqZWN0ZWQpDQogICAgICAgIHsNCiAgICAgICAgICAgIGlmICh0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWQpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIHIgPSBnZXRSb290UHJvbWlzZSh0aGlzKTsNCiAgICAgICAgICAgICAgICBpZihyLl9pbnRlcm5hbC51bmNhdWdodCAhPSBudWxsKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgY2xlYXJJbW1lZGlhdGUoci5faW50ZXJuYWwudW5jYXVnaHQpOw0KICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCByZWplY3RlZCkuZnVuYy5pbnRlcm5hbCk7DQogICAgICAgIH0NCiAgICAgICAgICANCiAgICAgICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKHByb21pc2VJbml0aWFsaXplcik7DQogICAgICAgIHJldFZhbC5wYXJlbnRQcm9taXNlID0gdGhpczsNCg0KICAgICAgICBpZiAodGhpcy5faW50ZXJuYWwuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICAvLyBUaGlzIHByb21pc2Ugd2FzIGFscmVhZHkgcmVzb2x2ZWQsIHNvIGxldHMgY2hlY2sgaWYgdGhlIGhhbmRsZXIgcmV0dXJuZWQgYSBwcm9taXNlDQogICAgICAgICAgICB2YXIgcnYgPSB0aGlzLl9pbnRlcm5hbC5lbWl0X3JldHVyblZhbHVlKCdyZXNvbHZlZCcpOw0KICAgICAgICAgICAgaWYocnYhPW51bGwpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgaWYocnYuX09iamVjdElEID09ICdwcm9taXNlJykNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHJ2LnBhcmVudFByb21pc2UgPSB0aGlzOw0KICAgICAgICAgICAgICAgICAgICBydi5faW50ZXJuYWwub25jZSgncmVzb2x2ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgICAgICAgICBydi5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlamVjdG9yLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyLmNhbGwocmV0VmFsLl9pbnRlcm5hbCwgcnYpOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGVsc2UNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZXNvbHZlZCcsIHJldFZhbC5faW50ZXJuYWwucmVzb2x2ZXIuYmluZChyZXRWYWwuX2ludGVybmFsKS5pbnRlcm5hbCk7DQogICAgICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlamVjdG9yLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgICAgIGVsc2UNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVzb2x2ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlamVjdG9yLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICB9DQoNCiAgICAgICAgdGhpcy5fX2NoaWxkUHJvbWlzZSA9IHJldFZhbDsNCiAgICAgICAgcmV0dXJuKHJldFZhbCk7DQogICAgfTsNCg0KICAgIHRyeQ0KICAgIHsNCiAgICAgICAgcHJvbWlzZUZ1bmMuY2FsbCh0aGlzLCB0aGlzLl9pbnRlcm5hbC5yZXNvbHZlci5iaW5kKHRoaXMuX2ludGVybmFsKSwgdGhpcy5faW50ZXJuYWwucmVqZWN0b3IuYmluZCh0aGlzLl9pbnRlcm5hbCkpOw0KICAgIH0NCiAgICBjYXRjaCAoZSkNCiAgICB7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmVycm9ycyA9IHRydWU7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCA9IHRydWU7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZEFyZ3MgPSBbZV07DQogICAgICAgIHRoaXMuX2ludGVybmFsLmVtaXQoJ3JlamVjdGVkJywgZSk7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmVtaXQoJ3NldHRsZWQnKTsNCiAgICB9DQoNCiAgICBpZighdGhpcy5faW50ZXJuYWwuY29tcGxldGVkKQ0KICAgIHsNCiAgICAgICAgLy8gU2F2ZSByZWZlcmVuY2Ugb2YgdGhpcyBvYmplY3QNCiAgICAgICAgcmVmVGFibGVbdGhpcy5faW50ZXJuYWwuX2hhc2hDb2RlKCldID0gdGhpcy5faW50ZXJuYWw7DQogICAgICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3NldHRsZWQnLCBmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICBkZWxldGUgcmVmVGFibGVbdGhpcy5faGFzaENvZGUoKV07DQogICAgICAgIH0pOw0KICAgIH0NCiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgImNvbXBsZXRlZCIsIHsNCiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICByZXR1cm4gKHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCk7DQogICAgICAgIH0NCiAgICB9KTsNCg0KICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3NldHRsZWQnLCAoZnVuY3Rpb24gKCkNCiAgICB7DQogICAgICAgIGRlbGV0ZSB0aGlzLnByb21pc2UuX3VwOw0KICAgICAgICBkZWxldGUgdGhpcy5wcm9taXNlLl9fY2hpbGRQcm9taXNlOw0KICAgICAgICBkZWxldGUgdGhpcy5wcm9taXNlLnByb21pc2U7DQoNCiAgICAgICAgZGVsZXRlIHRoaXMuX3VwOw0KICAgICAgICBkZWxldGUgdGhpcy5fX2NoaWxkUHJvbWlzZTsNCiAgICAgICAgZGVsZXRlIHRoaXMucHJvbWlzZTsNCiAgICAgICAgdGhpcy5yZW1vdmVBbGxMaXN0ZW5lcnMoJ3Jlc29sdmVkJyk7DQogICAgICAgIHRoaXMucmVtb3ZlQWxsTGlzdGVuZXJzKCdyZWplY3RlZCcpOw0KICAgIH0pLmludGVybmFsKTsNCn0NCg0KUHJvbWlzZS5yZXNvbHZlID0gZnVuY3Rpb24gcmVzb2x2ZSgpDQp7DQogICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IH0pOw0KICAgIHZhciBhcmdzID0gW107DQogICAgZm9yICh2YXIgaSBpbiBhcmd1bWVudHMpDQogICAgew0KICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2ldKTsNCiAgICB9DQogICAgcmV0VmFsLl9pbnRlcm5hbC5yZXNvbHZlci5hcHBseShyZXRWYWwuX2ludGVybmFsLCBhcmdzKTsNCiAgICByZXR1cm4gKHJldFZhbCk7DQp9Ow0KUHJvbWlzZS5yZWplY3QgPSBmdW5jdGlvbiByZWplY3QoKSB7DQogICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IH0pOw0KICAgIHZhciBhcmdzID0gW107DQogICAgZm9yICh2YXIgaSBpbiBhcmd1bWVudHMpIHsNCiAgICAgICAgYXJncy5wdXNoKGFyZ3VtZW50c1tpXSk7DQogICAgfQ0KICAgIHJldFZhbC5faW50ZXJuYWwucmVqZWN0b3IuYXBwbHkocmV0VmFsLl9pbnRlcm5hbCwgYXJncyk7DQogICAgcmV0dXJuIChyZXRWYWwpOw0KfTsNClByb21pc2UuYWxsID0gZnVuY3Rpb24gYWxsKHByb21pc2VMaXN0KQ0Kew0KICAgIHZhciByZXQgPSBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopDQogICAgew0KICAgICAgICB0aGlzLl9fcmVqZWN0b3IgPSByZWo7DQogICAgICAgIHRoaXMuX19yZXNvbHZlciA9IHJlczsNCiAgICAgICAgdGhpcy5fX3Byb21pc2VMaXN0ID0gcHJvbWlzZUxpc3Q7DQogICAgICAgIHRoaXMuX19kb25lID0gZmFsc2U7DQogICAgICAgIHRoaXMuX19jb3VudCA9IDA7DQogICAgfSk7DQoNCiAgICBmb3IgKHZhciBpIGluIHByb21pc2VMaXN0KQ0KICAgIHsNCiAgICAgICAgcHJvbWlzZUxpc3RbaV0udGhlbihmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICAvLyBTdWNjZXNzDQogICAgICAgICAgICBpZigrK3JldC5fX2NvdW50ID09IHJldC5fX3Byb21pc2VMaXN0Lmxlbmd0aCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXQuX19kb25lID0gdHJ1ZTsNCiAgICAgICAgICAgICAgICByZXQuX19yZXNvbHZlcihyZXQuX19wcm9taXNlTGlzdCk7DQogICAgICAgICAgICB9DQogICAgICAgIH0sIGZ1bmN0aW9uIChhcmcpDQogICAgICAgIHsNCiAgICAgICAgICAgIC8vIEZhaWx1cmUNCiAgICAgICAgICAgIGlmKCFyZXQuX19kb25lKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHJldC5fX2RvbmUgPSB0cnVlOw0KICAgICAgICAgICAgICAgIHJldC5fX3JlamVjdG9yKGFyZyk7DQogICAgICAgICAgICB9DQogICAgICAgIH0pOw0KICAgIH0NCiAgICBpZiAocHJvbWlzZUxpc3QubGVuZ3RoID09IDApDQogICAgew0KICAgICAgICByZXQuX19yZXNvbHZlcihwcm9taXNlTGlzdCk7DQogICAgfQ0KICAgIHJldHVybiAocmV0KTsNCn07DQoNCm1vZHVsZS5leHBvcnRzID0gUHJvbWlzZTsNCm1vZHVsZS5leHBvcnRzLmV2ZW50X3N3aXRjaGVyID0gZXZlbnRfc3dpdGNoZXI7DQptb2R1bGUuZXhwb3J0cy5ldmVudF9mb3J3YXJkZXIgPSBldmVudF9mb3J3YXJkZXI7DQptb2R1bGUuZXhwb3J0cy5kZWZhdWx0SW5pdCA9IGZ1bmN0aW9uIGRlZmF1bHRJbml0KHJlcywgcmVqKSB7IHRoaXMucmVzb2x2ZSA9IHJlczsgdGhpcy5yZWplY3QgPSByZWo7IH0=', 'base64').toString());
var promise = require('promise2');
function promise_default(res, rej)
{
    this._res = res;
    this._rej = rej;
}


function  buf2addr(buf)
{
    return (buf[0] + '.' + buf[1] + '.' + buf[2] + '.' + buf[3]);
}
function parseDHCP(buffer)
{
    var i;
    var packet = Buffer.alloc(buffer.length);
    for (i = 0; i < buffer.length; ++i) { packet[i] = buffer[i]; }

    var ret = { op: packet[0] == 0 ? 'REQ' : 'RES', hlen: packet[2] };   // OP Code
    ret.xid = packet.readUInt32BE(4);                   // Transaction ID
    ret.ciaddr = buf2addr(packet.slice(12, 16));
    ret.yiaddr = buf2addr(packet.slice(16, 20)); 
    ret.siaddr = buf2addr(packet.slice(20, 24));
    ret.giaddr = buf2addr(packet.slice(24, 28));
    ret.chaddr = packet.slice(28, 28 + ret.hlen).toString('hex:');
    if (packet[236] == 99 && packet[237] == 130 && packet[238] == 83 && packet[239] == 99)
    {
        // Magic Cookie Validated
        ret.magic = true;
        ret.options = {};

        i = 240;
        while(i<packet.length)
        {
            switch(packet[i])
            {
                case 0:
                    i += 1;
                    break;
                case 255:
                    ret.options[255] = true;
                    i += 2;
                    break;
                default:
                    ret.options[packet[i]] = packet.slice(i + 2, i + 2 + packet[i + 1]);
                    switch(packet[i])
                    {
                        case 1:     // Subnet Mask
                            ret.options.subnetmask = buf2addr(ret.options[1]);
                            delete ret.options[1];
                            break;
                        case 3:     // Router
                            ret.options.router = [];
                            var ti = 0;
                            while (ti < ret.options[3].length)
                            {
                                ret.options.router.push(buf2addr(ret.options[3].slice(ti, ti + 4)));
                                ti += 4;
                            }
                            delete ret.options[3];
                            break;
                        case 6:     // DNS
                            ret.options.dns = buf2addr(ret.options[6]);
                            delete ret.options[6];
                            break;
                        case 15:    // Domain Name
                            ret.options.domainname = ret.options[15].toString();
                            delete ret.options[15];
                            break;
                        case 28:    // Broadcast Address
                            ret.options.broadcastaddr = buf2addr(ret.options[28]);
                            delete ret.options[28];
                            break;
                        case 51:    // Lease Time
                            ret.options.lease = { raw: ret.options[51].readInt32BE() };
                            delete ret.options[51];
                            ret.options.lease.hours = Math.floor(ret.options.lease.raw / 3600);
                            ret.options.lease.minutes = Math.floor((ret.options.lease.raw % 3600) / 60);
                            ret.options.lease.seconds = (ret.options.lease.raw % 3600) % 60;
                            break;
                        case 53:    // Message Type
                            ret.options.messageType = ret.options[53][0];
                            delete ret.options[53];
                            break;  
                        case 54:    // Server
                            ret.options.server = buf2addr(ret.options[54]);
                            delete ret.options[54];
                            break;
                    }
                    i += (2 + packet[i + 1]);
                    break;
            }
        }
    }


    return (ret);
}

function createPacket(messageType, data)
{
    var b = Buffer.alloc(245);

    switch(messageType)
    {
        //case 0x02:
        //case 0x04:
        //case 0x05:
        //case 0x06:
        //    b[0] = 0x00;      // Reply
        //    break;
        //case 0x01:
        //case 0x03:
        //case 0x07:
        case 0x08:
            b[0] = 0x01;        // Request
            break;
        default:
            throw ('DHCP(' + messageType + ') NOT SUPPORTED');
            break;
    }

    // Headers
    b[1] = 0x01;        // Ethernet
    b[2] = 0x06;        // HW Address Length
    b[3] = 0x00;        // HOPS

    // Transaction ID
    var r = Buffer.alloc(4); r.randomFill();
    b.writeUInt32BE(r.readUInt32BE(), 4);
    b.writeUInt16BE(0x8000, 10);

    // Magic Cookie
    b[236] = 99;
    b[237] = 130;
    b[238] = 83;
    b[239] = 99;

    // DHCP Message Type
    b[240] = 53;
    b[241] = 1;
    b[242] = messageType;
    b[243] = 255;

    switch(messageType)
    {
        case 0x08:
            if (data.ciaddress == null) { throw ('ciadress missing'); }
            if (data.chaddress == null) { throw ('chaddress missing'); }

            // ciaddress
            var a = data.ciaddress.split('.');
            var ci = parseInt(a[0]);
            ci = ci << 8;
            ci = ci | parseInt(a[1]);
            ci = ci << 8;
            ci = ci | parseInt(a[2]);
            ci = ci << 8;
            ci = ci | parseInt(a[3]);
            b.writeInt32BE(ci, 12);

            // chaddress
            var y = data.chaddress.split(':').join('');
            y = Buffer.from(y, 'hex');
            y.copy(b, 28);

            break;
    }

    return (b);
}

function raw(localAddress, port, buffer, handler)
{
    var ret = new promise(promise_default);
    ret.socket = require('dgram').createSocket({ type: 'udp4' });
    try
    {
        ret.socket.bind({ address: localAddress, port: (port != null && port != 0) ? port : null });
    }
    catch (e)
    {
        ret._rej('Unable to bind to ' + localAddress);
        return (ret);
    }

    ret.socket.setBroadcast(true);
    ret.socket.setMulticastInterface(localAddress);
    ret.socket.setMulticastTTL(1);
    ret.socket.descriptorMetadata = 'DHCP (' + localAddress + ')';
    ret.socket.on('message', handler.bind(ret));
    ret.socket.send(buffer, 67, '255.255.255.255');
    return (ret);
}

function info(interfaceName, port)
{
    var f = require('os').networkInterfaces();
    if (f[interfaceName] != null)
    {
        var i;
        for(i=0;i<f[interfaceName].length;++i)
        {
            if(f[interfaceName][i].family == 'IPv4' && f[interfaceName][i].mac != '00:00:00:00:00:00')
            {
                try
                {
                    var b = createPacket(8, { ciaddress: f[interfaceName][i].address, chaddress: f[interfaceName][i].mac });
                    _hide(raw(f[interfaceName][i].address, port, b, function infoHandler(msg)
                    {
                        try
                        {
                            var res = parseDHCP(msg);
                            if (res.chaddr.toUpperCase() == this.hwaddr.toUpperCase() && res.options != null && res.options.lease != null)
                            {
                                clearTimeout(this.timeout);
                                setImmediate(function (s) { try { s.removeAllListeners('message'); } catch (x) { } }, this.socket); // Works around bug in older dgram.js
                                this._res(res);
                            }
                        }
                        catch(z)
                        {
                        }
                    }));
                    _hide().hwaddr = f[interfaceName][i].mac;
                    _hide().timeout = setTimeout(function (x)
                    {
                        x.socket.removeAllListeners('message');
                        x._rej('timeout');
                    }, 2000, _hide());
                    return (_hide(true));
                }
                catch(e)
                {
                    var ret = new promise(promise_default);
                    ret._rej(e);
                    return (ret);
                }
            }
        }
    }

    var ret = new promise(promise_default);
    ret._rej('interface (' + interfaceName + ') not found');
    return (ret);
}

module.exports = 
    {
        client: { info: info, raw: raw }, 
        MESSAGE_TYPES: 
            {
                DISCOVER: 1,
                OFFER: 2,
                REQUEST: 3,
                DECLINE: 4,
                ACK: 5,
                NACK: 6,
                RELEASE: 7,
                INFO: 8 
            } 
    };

