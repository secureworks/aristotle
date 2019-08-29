import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { BuildFilterComponent } from './build-filter.component';

describe('BuildFilterComponent', () => {
  let component: BuildFilterComponent;
  let fixture: ComponentFixture<BuildFilterComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ BuildFilterComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(BuildFilterComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
