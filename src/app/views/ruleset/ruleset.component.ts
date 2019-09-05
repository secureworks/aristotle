import { Component, OnInit } from '@angular/core';
import { GridOptions } from "ag-grid-community";
//import { saveAs } from 'file-saver';
import { colDefs_Rules } from '../../_models/grid-support'

@Component({
  selector: 'app-ruleset',
  templateUrl: './ruleset.component.html',
  styleUrls: ['./ruleset.component.scss']
})
export class RulesetComponent implements OnInit {

  filename: any;
  rules: string[];

  private gridApi;
  private gridColumnApi;

  public columnDefs;
  public autoGroupColumnDef;
  public defaultColDef;
  public rowSelection;
  public rowGroupPanelShow;
  public pivotPanelShow;
  public rowData: any[];
  public lines;
  

  constructor() {
    this.columnDefs = colDefs_Rules;
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
  
  createNewRowData (ruleString, index) {
      // var newData: any;
      if (ruleString.startsWith("#")) {
        var newData = {
          ruleid: index,
          default: "Disabled",
          rule: ruleString.substr(1)
        };
      }
      else {
        var newData = {
          ruleid: index,
          default: "Enabled",
          rule: ruleString
        };
      }
      return newData;
  }

  loadDocument(filename) {
      const rowData: any[] = [];
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
    let FileSaver = require('file-saver');
    var content = this.buildFileContent();
    var blob = new Blob([content], {type: "text/plain;charset=utf-8"});
    FileSaver.saveAs(blob, "out.txt");
  }
 
  ngOnInit() {
  }



}
