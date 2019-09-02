import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { ClarityModule } from '@clr/angular';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { UiModule } from './views/ui/ui.module';
import { AgGridModule } from 'ag-grid-angular';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { RulesetComponent } from './views/ruleset/ruleset.component';
import { MetadataComponent } from './views/metadata/metadata.component';
import { BuildFilterComponent } from './views/build-filter/build-filter.component';

@NgModule({
  declarations: [
    AppComponent, RulesetComponent, MetadataComponent, BuildFilterComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    ClarityModule,
    BrowserAnimationsModule,
    UiModule,
    AgGridModule.withComponents([]),
    FormsModule,
    ReactiveFormsModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
