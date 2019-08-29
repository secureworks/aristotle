import { Component, OnInit } from '@angular/core';
// import { GridOptions } from "ag-grid-community";
import { saveAs } from 'file-saver';
// import { colDefs_Metadata } from '../../_models/grid-support'
import { Kvpair, Kvrecord } from '../../_models/kvpair';
import { Rule } from '../../_models/rule';
import { ParserService } from '../../_services/parser.service';
import { KvpairService } from '../../_services/kvpair.service';

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

  constructor(private parser: ParserService, private kvpairService: KvpairService) {
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
  } 

  getKVstatics(key: string, value: string) {
    var kvrecord = this.kvpairService.getKvrecordByKV(this.kvrecords, key, value);

    var elen = kvrecord.enables.length;
    var dlen = kvrecord.disables.length;
    var total = elen+dlen;
    return "Total: "+ total + "; Enabled:" + elen + ";  Disabled: " + dlen;
  }

  buildFileContent() {
    var content = '';
    
    return content;
  }
  
  saveFile() {
    var require: any;
    var FileSaver = require('file-saver');
    var content = this.buildFileContent();
    var blob = new Blob([content], {type: "text/plain;charset=utf-8"});
    FileSaver.saveAs(blob, "out.txt");
  }

  buildFilter(){}

  exportFilter(){}
 
  ngOnInit() {
  }



}


