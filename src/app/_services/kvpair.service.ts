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

  // Retrieve Kvpair by key
  getKvrecordByKV(kvrecords: Kvrecord[], key: string, value: string): Kvrecord {
    for (var i = 0; i < kvrecords.length; i++) {
      if (kvrecords[i].key === key && kvrecords[i].value === value) {
        return kvrecords[i];
      }
    }
    return null;
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

  updateKvrecordEnables(kvrecord: Kvrecord, id: string): boolean {
    kvrecord.enables.push(id);
    return true;
  }

  updateKvrecordDisables(kvrecord: Kvrecord, id: string): boolean {
    kvrecord.disables.push(id);
    return true;
  }

  // Updata a Kvrecord, change a sid from enables list to disables list
  // rule id is unique, if use sid, then sid needs to be unique
  updateKvrecordE2D(kvrecord: Kvrecord, id: string): boolean {
    for (var i =0; i < kvrecord.enables.length; i++) {
      if (kvrecord.enables[i] === id) {
        kvrecord.enables.splice(i,1);
      }
    }
    kvrecord.disables.push(id);
    
    return true;
  }

  // Updata a Kvrecord, change a sid from disables list to enables list
  // rule id is unique, if use sid, then sid needs to be unique
  updateKvrecordD2E(kvrecord: Kvrecord, id: string): boolean {
    for (var i =0; i < kvrecord.disables.length; i++) {
      if (kvrecord.disables[i] === id) {
        kvrecord.disables.splice(i,1);
      }
    }
    kvrecord.enables.push(id);
    
    return true;
  }


}
