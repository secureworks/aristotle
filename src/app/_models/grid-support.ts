export const colDefs_Rules: Array<Object> = [
	{
		headerName: "Rule ID",
		field: "ruleid",
		width: 120,
		checkboxSelection: function(params) {
			return params.columnApi.getRowGroupColumns().length === 0;
		},
		headerCheckboxSelection: function(params) {
			return params.columnApi.getRowGroupColumns().length === 0;
		},
		sortable: true,
		sort: 'asc'
	},
	{
		headerName: "Default Setting",
		field: "default",
		width: 165,
		filter: true,
		sortable: true,
		sort: 'desc',
		// enterprise version: enableRowGroup: true,
		cellStyle: function (params) {
			switch (params.value) {
			case 'Enabled':
					return { backgroundColor: 'lightblue' };
			case 'Disabled':
					return { backgroundColor: 'red' };
			default:
					return null;
			}
		}
  },
  {
    headerName: "Rule Details",
    field: "rule",
    width: 1300,
    autoHeight: true,
    cellStyle: {'white-space': 'normal'}
  }
];

export const colDefs_Metadata: Array<Object> = [
	{
		headerName: "Rule ID",
		field: "ruleid",
		width: 120,
		checkboxSelection: function(params) {
			return params.columnApi.getRowGroupColumns().length === 0;
		},
		headerCheckboxSelection: function(params) {
			return params.columnApi.getRowGroupColumns().length === 0;
		},
		sortable: true,
		sort: 'asc'
	},
	{
		headerName: "Default Setting",
		field: "default",
		width: 150,
		filter: true,
		sortable: true,
		sort: 'desc',
		// enterprise version: enableRowGroup: true,
		cellStyle: function (params) {
			switch (params.value) {
			case 'Enabled':
					return { backgroundColor: 'lightblue' };
			case 'Disabled':
					return { backgroundColor: 'red' };
			default:
					return null;
			}
		}
	},
	{
		headerName: "capec_id",
    field: "capec_id"
	},
	{
		headerName: "created_at",
    field: "created_at"
	},
	{
		headerName: "cve",
    field: "cve"
	},
	{
		headerName: "cvss_v2_base",
    field: "cvss_v2_base"
	},
	{
		headerName: "cvss_v2_temporal",
    field: "cvss_v2_temporal"
	},
	{
		headerName: "cvss_v3_base",
    field: "cvss_v3_base"
	},
	{
		headerName: "cvss_v3_temporal",
    field: "cvss_v3_temporal"
	},
	{
		headerName: "cwe_id",
    field: "cwe_id"
	},
	{
		headerName: "filenamel",
    field: "filename"
	},
	{
		headerName: "malware",
    field: "malware"
	},
	{
		headerName: "priority",
    field: "priority"
	},
	{
		headerName: "protection_target",
    field: "protection_target"
	},
	{
		headerName: "protocols",
    field: "protocols"
	},
	{
		headerName: "rule_source",
    field: "rule_source"
	},
	{
		headerName: "target",
    field: "target"
	},
	{
		headerName: "updated_at",
    field: "updated_at"
	},
	{
		headerName: "vendor_patch",
    field: "vendor_patch"
	},
	{
    headerName: "Rule Details",
    field: "rule",
    width: 300,
    autoHeight: true,
    cellStyle: {'white-space': 'normal'}
  }
];

export const colDefs_Kvpair: Array<Object> = [
	{
		headerName: "SID",
		field: "rulesid",
		width: 120,
		checkboxSelection: function(params) {
			return params.columnApi.getRowGroupColumns().length === 0;
		},
		headerCheckboxSelection: function(params) {
			return params.columnApi.getRowGroupColumns().length === 0;
		},
		sortable: true,
		sort: 'asc'
	},
	{
		headerName: "Enabled",
		field: "default",
		width: 100,
		filter: true,
		sortable: true,
		sort: 'desc',
		// enterprise version: enableRowGroup: true,
		cellStyle: function (params) {
			if (params.value) {
				return { backgroundColor: 'lightblue' };
			}
			else {
					return { backgroundColor: 'red' };
			}
			
		}
  },
  {
    headerName: "Rule Details",
    field: "rule",
    width: 800,
    autoHeight: true,
    cellStyle: {'white-space': 'normal'}
  }
];