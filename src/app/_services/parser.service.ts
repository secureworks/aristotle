import { Injectable } from '@angular/core';
import { Rule } from '../_models/rule';
import { Kvpair, Kvrecord } from '../_models/kvpair';
import { KvpairService } from './kvpair.service';
import { Observable, of } from 'rxjs';


@Injectable({
  providedIn: 'root'
})

export class ParserService {

  constructor(private kvpairService: KvpairService) { }

  // Parse the rule string (without #) and get Metadata
  getSid (ruleString) {
    var position = ruleString.indexOf('sid:');

    if (position !== -1) {
      // remove "sid:" from the beginning as well
      var sid = ruleString.substr(position+4).split(';')[0];
      return sid;
    }
    else {
      return null;
    }
  }

  // Parse the rule string (without #) and get Metadata string
  getMetadataString (ruleString: string) {
    var position = ruleString.indexOf('metadata:');

    if (position !== -1) {
      // remove "metadata:" from the beginning as well
      var mString = ruleString.substr(position+9).split(';')[0];
      return mString;
    }
    else {
      return null;
    }
  }

  // Parse the metadata string and get key-value pairs, also updata the key-value pairs for whole ruleset
  // and updata kvrecords
  getMetadata (kvpairs: Kvpair[], mString: string, kvrecords: Kvrecord[], rule: Rule) {
    // a set of key-value for this rule
    var ruleKvpairs: Kvpair[] = [];
    // get key-value pairs
    var pairs = mString.split(",");
    for(var i = 0; i < pairs.length; i++) {
      var key = pairs[i].trim().split(" ")[0];
      var value = pairs[i].trim().split(" ")[1];
      // update this rule's metadata, 
      let ruleKvpair = this.kvpairService.getKvpairByKey(ruleKvpairs, key);
      if (ruleKvpair !== null) {
        this.kvpairService.updateKvpairValues(ruleKvpair,value);
      }
      else {
        // create a new key-value pair
        var newRuleKvpair = new Kvpair();
        newRuleKvpair.key = key;
        newRuleKvpair.values.push(value);
        this.kvpairService.addKvpair(ruleKvpairs, newRuleKvpair);
      }
     
      // now update the whole ruleset's kvpairs
      let kvpair = this.kvpairService.getKvpairByKey(kvpairs, key);
      if (kvpair !== null) {
        this.kvpairService.updateKvpairValues(kvpair,value);
      }
      else {
        // create a new key-value pair
        var newKvpair = new Kvpair();
        newKvpair.key = key;
        newKvpair.values.push(value);
        this.kvpairService.addKvpair(kvpairs, newKvpair);
      }
      
      
      // update the kvrecords
      let str = key.concat(" ").concat(value);
      let kvrecord = this.kvpairService.getKvrecordByStr(kvrecords, str);
      if (kvrecord !== null) {
        if (rule.enabled) {
          this.kvpairService.updateKvrecordEnables(kvrecord, rule.sid);
        }
        else {
          this.kvpairService.updateKvrecordDisables(kvrecord, rule.sid);
        }
      }
      else {
        // create a new key-value record
        var newKvrecord = new Kvrecord();
        newKvrecord.key = key;
        newKvrecord.value = value;
        newKvrecord.selected = false;
        newKvrecord.filterStr = str;
        if (rule.enabled) {
          newKvrecord.enables.push(rule.sid);
        }
        else {
          newKvrecord.disables.push(rule.sid);
        }
        this.kvpairService.addKvrecord(kvrecords, newKvrecord);
      }
    }
    rule.metadata = ruleKvpairs;
  }




}
