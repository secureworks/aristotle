import { Kvpair } from './kvpair';

export class Rule {
  id: string;
  sid: string;
  metadata: Kvpair[] = [];
  enabled: boolean;
  description: string;
}
