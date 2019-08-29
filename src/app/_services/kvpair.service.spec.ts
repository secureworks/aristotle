import { TestBed } from '@angular/core/testing';

import { KvpairService } from './kvpair.service';

describe('KvpairService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: KvpairService = TestBed.get(KvpairService);
    expect(service).toBeTruthy();
  });
});
