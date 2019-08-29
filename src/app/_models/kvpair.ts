// a key-value pair for metadata
export class Kvpair {
  key: string;
  values: string[] = [];
}

// key-value pair with rule info (sid) for whole fileset
export class Kvrecord {
  key: string;
  value: string;
  enables: string[] = [];
  disables: string[] = [];
}
