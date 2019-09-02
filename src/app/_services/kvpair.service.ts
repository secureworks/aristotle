import { Injectable } from '@angular/core';
import { Kvpair, Kvrecord } from '../_models/kvpair';
import { Observable, of } from 'rxjs';
@Injectable({
  providedIn: 'root'
})
export class KvpairService {
  constructor() { }
  
  // Retrieve Kvpair by key
  getKvpairByKey(kvpairs: Kvpair[], key: string): Kvpair {
    for (var i = 0; i < kvpairs.length; i++) {
      if (kvpairs[i].key === key) {
        return kvpairs[i];
      }
    }
    return null;
  }

  // Retrieve Kvpair by key
  // getKvpairByKey(kvpairs: Kvpair[], key: string): Observable<Kvpair> {
  //   return of(kvpairs.find(kvpair => kvpair.key === key));
  // }

  // Retrieve a list of Kvrecords by key
  getKvrecordByK(kvrecords: Kvrecord[], key: string): Kvrecord[] {
    var newKvrecords: Kvrecord[] = [];
    for (var i = 0; i < kvrecords.length; i++) {
      if (kvrecords[i].key === key) {
        newKvrecords.push(kvrecords[i]);
      }
    }
    return newKvrecords;
  }

  // Retrieve Kvrecord by key & value
  getKvrecordByKV(kvrecords: Kvrecord[], key: string, value: string): Kvrecord {
    for (var i = 0; i < kvrecords.length; i++) {
      if (kvrecords[i].key === key && kvrecords[i].value === value) {
        return kvrecords[i];
      }
    }
    return null;
  }

  // Retrieve Kvrecord by filterStr which is in format of "key value"
  // this should be quick than getKvrecordByKV since there are only one cpmparison
  getKvrecordByStr(kvrecords: Kvrecord[], filterStr: string): Kvrecord {
    for (var i = 0; i < kvrecords.length; i++) {
      if (kvrecords[i].filterStr === filterStr) {
        return kvrecords[i];
      }
    }
    return null;
  }

  // Retrieve a list of Kvrecords that has been selected
  getKvrecordSelected(kvrecords: Kvrecord[]): Kvrecord[] {
    var newKvrecords: Kvrecord[] = [];
    for (var i = 0; i < kvrecords.length; i++) {
      if (kvrecords[i].selected) {
        newKvrecords.push(kvrecords[i]);
      }
    }
    return newKvrecords;
  }

  // Add a new Kvpair
  addKvpair(oldKvpairs: Kvpair[], newKvpair: Kvpair): boolean {
    oldKvpairs.push(newKvpair);
    return true;
  }

  // Updata a Kvrecord, change a sid from enables list to disables list
  // rule id is unique, if use sid, then sid needs to be unique
  updateKvpairValues(kvpair: Kvpair, value: string): boolean {
    if (!kvpair.values.includes(value)) {
      kvpair.values.push(value);
    }
    
    return true;
  }

  // Add a new Kvpair
  addKvrecord(oldKvrecords: Kvrecord[], newKvrecord: Kvrecord): boolean {
    oldKvrecords.push(newKvrecord);
    return true;
  }

  updateKvrecordEnables(kvrecord: Kvrecord, sid: string): boolean {
    kvrecord.enables.push(sid);
    return true;
  }

  updateKvrecordDisables(kvrecord: Kvrecord, sid: string): boolean {
    kvrecord.disables.push(sid);
    return true;
  }

  // Updata a Kvrecord, change a sid from enables list to disables list
  // assume sid is unique
  updateKvrecordE2D(kvrecord: Kvrecord, sid: string): boolean {
    for (var i =0; i < kvrecord.enables.length; i++) {
      if (kvrecord.enables[i] === sid) {
        kvrecord.enables.splice(i,1);
      }
    }
    kvrecord.disables.push(sid);
    
    return true;
  }

  // Updata a Kvrecord, change a sid from disables list to enables list
  // assume sid is unique
  updateKvrecordD2E(kvrecord: Kvrecord, sid: string): boolean {
    for (var i =0; i < kvrecord.disables.length; i++) {
      if (kvrecord.disables[i] === sid) {
        kvrecord.disables.splice(i,1);
      }
    }
    kvrecord.enables.push(sid);
    
    return true;
  }


}
