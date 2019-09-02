import { Component, OnInit } from '@angular/core';
import { GridOptions } from "ag-grid-community";
import { colDefs_Kvpair } from '../../_models/grid-support'
import { Kvpair, Kvrecord } from '../../_models/kvpair';
import { Rule } from '../../_models/rule';
import { ParserService } from '../../_services/parser.service';
import { KvpairService } from '../../_services/kvpair.service';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

@Component({
  selector: 'app-build-filter',
  templateUrl: './build-filter.component.html',
  styleUrls: ['./build-filter.component.scss']
})
export class BuildFilterComponent implements OnInit {

  inputFileName: any;
  rules: Rule[] = [];
  kvpairs: Kvpair[] = [];
  kvrecords: Kvrecord[] = [];
  selItems = [];
  filterForm: FormGroup;
  filterStr: string;

  // rules grid
  private gridApi;
  private gridColumnApi;

  private columnDefs;
  // private autoGroupColumnDef;
  private defaultColDef;
  private rowSelection;
  private rowGroupPanelShow;
  private pivotPanelShow;
  private rowData: any[];

  constructor(
    private parser: ParserService,
    private kvpairService: KvpairService,
    private formBuilder: FormBuilder) {
      this.columnDefs = colDefs_Kvpair;
      this.rowSelection = "multiple";
      this.rowGroupPanelShow = "always";
      this.pivotPanelShow = "always";
  }

  onGridReady(params) {
    this.gridApi = params.api;
    this.gridColumnApi = params.columnApi;
  }

  selectAllEnabled() {
    
    this.gridApi.forEachNode(function(node) {
      if (node.data.default) {
        node.setSelected(true);
      }
    });
  } 
  
  fileChanged(e) {
    this.inputFileName = e.target.files[0];
    console.log(this.inputFileName)
    this.loadDocument(this.inputFileName);
  }

  createNewRule (ruleString, index) {
    var rule = new Rule();
    rule.id = index;
    if (ruleString.startsWith("#")) {
      ruleString = ruleString.substr(1);
      rule.enabled = false;
    }
    else {
      rule.enabled = true;
    }
    rule.sid = this.parser.getSid(ruleString);
    if (rule.sid === null) {
      console.log("empty sid, id: " + index);
    }
    var mString = this.parser.getMetadataString(ruleString);
    if (mString !== null) {
      this.parser.getMetadata(this.kvpairs, mString, this.kvrecords, rule);
    }
    else {
      console.log("empty metadata, id: " + index);
      rule.metadata = [];
    }
    rule.description = ruleString;
    return rule;
  }

  // Load the file, firstly parse every rule, extract sid and metadata,
  // and build key-value pairs for all ruleset and each rule
  loadDocument(filename) {
    let fileReader = new FileReader();
    var ruleStrings: string[];
    fileReader.onloadend = (e) => {
      const ruleset = fileReader.result; // `string | ArrayBuffer` type is inferred for you
      
      // check ruleset type
      if (typeof ruleset === 'string') {ruleStrings = ruleset.split('\n');}
      else {ruleStrings = ruleset.toString().split('\n');}
    
      for(var line = 0; line < ruleStrings.length; line++){
        if (ruleStrings[line] !== "") {
          var rule = this.createNewRule(ruleStrings[line], line+1)
          this.rules.push(rule);
        }
      }


      // console.log(this.kvpairs);
      // console.log(this.kvrecords);
    };

    fileReader.readAsText(this.inputFileName);

    this.filterForm = this.formBuilder.group({
      filterStrs: ['', Validators.required],
    });
  } 

  getKVStatics(key: string, value: string) {
    var kvrecord = this.kvpairService.getKvrecordByKV(this.kvrecords, key, value);

    var elen = kvrecord.enables.length;
    var dlen = kvrecord.disables.length;
    var total = elen+dlen;
    return "Total: "+ total + "; Enabled:" + elen + ";  Disabled: " + dlen;
  }

  showStatics(kvrecord: Kvrecord) {
    var elen = kvrecord.enables.length;
    var dlen = kvrecord.disables.length;
    var total = elen+dlen;
    return "Total: "+ total + "; Enabled:" + elen + ";  Disabled: " + dlen;
  }

  getKVStr(key: string, value: string) {
    var str = key.concat(" ").concat(value);
    var kvrecord = this.kvpairService.getKvrecordByStr(this.kvrecords, str);

    return kvrecord.selected;
  }

  getKvrecordByK(key: string) {
    return this.kvpairService.getKvrecordByK(this.kvrecords, key);
  }

  getSelectedRecordStrs() {
    var filterStrings:string[] = [];
    var kvrecords = this.kvpairService.getKvrecordSelected(this.kvrecords);
    for (var i = 0; i < kvrecords.length; i++) {
      var str = "\"";
      filterStrings.push(str.concat(kvrecords[i].filterStr).concat("\""));
    }
    return filterStrings.sort();
  }

  buildFilter() {
    var showStrs = this.getSelectedRecordStrs();
    this.filterForm.patchValue({filterStrs: showStrs.join(' OR ')});
  }

  getRuleData(kvrecord: Kvrecord) {
    const rowData: any[] = [];
    var sids = kvrecord.enables.concat(kvrecord.disables);
    var returnRules: Rule[] = [];
    for (var i = 0; i < this.rules.length; i++) {
      if (sids.includes(this.rules[i].sid)) {
        var newData = {};
        newData["rulesid"] = this.rules[i].sid;
        newData["default"] = this.rules[i].enabled;
        newData["rule"] = this.rules[i].description;
        rowData.push(newData);
      }
    }
    return rowData;
  }

  showRules(kvrecord: Kvrecord, filterStr: string) {
    this.filterStr = filterStr;
    this.gridApi.setRowData(this.getRuleData(kvrecord));
    this.selectAllEnabled(); 
  }

  getSelectedKVStr() {
    return this.filterStr 
  }

  resetForm() {
    this.filterForm.reset();
  }

  save(): void {
    var require: any;
    let FileSaver = require('file-saver');
    
    // updated the operation[]
    if (this.filterForm.invalid) {
      return;
    }
    // return the new record
    var content = this.filterForm.controls.filterStrs.value;
    var blob = new Blob([content], {type: "text/plain;charset=utf-8"});
    FileSaver.saveAs(blob, "filter.txt");
  }

  ngOnInit() {
  }



}


