import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { RulesetComponent } from './ruleset.component';

describe('RulesetComponent', () => {
  let component: RulesetComponent;
  let fixture: ComponentFixture<RulesetComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ RulesetComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(RulesetComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
