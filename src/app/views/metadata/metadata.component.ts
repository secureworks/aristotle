import { Component, OnInit } from '@angular/core';
import { GridOptions } from "ag-grid-community";
import { saveAs } from 'file-saver';
import { colDefs_Metadata } from '../../_models/grid-support'

@Component({
  selector: 'app-metadata',
  templateUrl: './metadata.component.html',
  styleUrls: ['./metadata.component.scss']
})
export class MetadataComponent implements OnInit {

  filename: any;
  rules: string[];
  keys: string[];

  private gridApi;
  private gridColumnApi;

  private columnDefs;
  // private autoGroupColumnDef;
  private defaultColDef;
  private rowSelection;
  private rowGroupPanelShow;
  private pivotPanelShow;
  private rowData: any[];

  constructor() {
    this.columnDefs = colDefs_Metadata;
    this.defaultColDef = {
      width: 150,
      filter: true,
      sortable: true
    }
    this.rowSelection = "multiple";
    this.rowGroupPanelShow = "always";
    this.pivotPanelShow = "always";
  }

  onGridReady(params) {
    this.gridApi = params.api;
    this.gridColumnApi = params.columnApi;
  }

  fileChanged(e) {
    this.filename = e.target.files[0];
    console.log(this.filename)
    this.loadDocument(this.filename);
      
  }

  // Parse the rule string (without #) and get Metadata
  getMetadata (ruleString) {
    var position = ruleString.indexOf('metadata:');

    if (position !== -1) {
      // remove "metadata:" from the beginning as well
      var mString = ruleString.substr(position+9).split(';')[0];
      this.getKeys (mString);
      return mString;
    }
    else {
      return null;
    }
    
  }

  getKeys (mString) {
    // get key-value pairs
    var pairs = mString.split(", ");
    for(var i = 0; i < pairs.length; i++) {
      var key = pairs[i].split(" ")[0];
      if (!this.keys.includes(key)) {
        // console.log(key);
        this.keys.push(key);
      }
    }
  }

  getKeyValues(mString) {
    var pairs = mString.split(", ");
    var keyValues = {};
    // there is multiple entry for same key
    // keyValues[ pairs[0] ] = pairs[1];
    for(var i = 0; i < pairs.length; i++) {
      
      var key = pairs[i].split(" ")[0];
      var value = pairs[i].split(" ")[1];
      if (!(key in keyValues)) {
        keyValues[key] = value;
      }
      else {
        keyValues[key] = keyValues[key].concat(",").concat(value);
      }

    }

    return keyValues;
  }
  
  createNewRowData (ruleString, index) {
      var newData = {};
      if (ruleString.startsWith("#")) {
        var mString = this.getMetadata (ruleString.substr(1));
        
        if (mString != null) {
          newData = this.getKeyValues(mString);
        }
        newData["ruleid"] = index;
        newData["default"] = "Disabled";
        newData["rule"] = ruleString.substr(1);
        // var newData = {
        //   ruleid: index,
        //   default: "Disabled",
        //   protocols: "http",
        //   rule: ruleString.substr(1)
        // };
        
      }
      else {
        var mString = this.getMetadata (ruleString);
        if (mString != null) {
          newData = this.getKeyValues(mString);
        }
        newData["ruleid"] = index;
        newData["default"] = "Enabled";
        newData["rule"] = ruleString;
        // var newData = {
        //   ruleid: index,
        //   default: "Enabled",
        //   protocols: "tcp",
        //   rule: ruleString
        // };
      }
      return newData;
  }

  loadDocument(filename) {
      const rowData: any[] = [];
      this.keys = [];
      let fileReader = new FileReader();
      fileReader.onloadend = (e) => {
        const ruleset = fileReader.result; // `string | ArrayBuffer` type is inferred for you
        // check ruleset type
        
        if (typeof ruleset === 'string') {this.rules = ruleset.split('\n');}
        else {this.rules = ruleset.toString().split('\n');}
      
        for(var line = 0; line < this.rules.length; line++){
          var newData = this.createNewRowData(this.rules[line], line+1)
          rowData.push(newData);
        }
        // this.rowData = rowData;
        this.gridApi.setRowData(rowData);
        this.selectAllEnabled(); 
        this.keys.sort();
        console.log(this.keys);
      };

      fileReader.readAsText(this.filename);
  } 

  selectAllEnabled() {
    
    this.gridApi.forEachNode(function(node) {
      if (node.data.default === "Enabled") {
        node.setSelected(true);
      }
    });
  }  

  buildFileContent() {
    var content = '';
    this.gridApi.forEachNode(function(node) {
      if (node.isSelected()) {
        content = content.concat(node.data.rule);
        content = content.concat("\n");
      }
      else {
        content = content.concat("#");
        content = content.concat(node.data.rule);
        content = content.concat("\n");
      }
    });
    return content;
  }
  
  saveFile() {
    var require: any;
    var FileSaver = require('file-saver');
    var content = this.buildFileContent();
    var blob = new Blob([content], {type: "text/plain;charset=utf-8"});
    FileSaver.saveAs(blob, "out.txt");
  }
 
  ngOnInit() {
  }



}

