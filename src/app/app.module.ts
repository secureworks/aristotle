import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { ClarityModule } from '@clr/angular';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { UiModule } from './views/ui/ui.module';
import { AgGridModule } from 'ag-grid-angular';

import { RulesetComponent } from './views/ruleset/ruleset.component';
import { MetadataComponent } from './views/metadata/metadata.component';

@NgModule({
  declarations: [
    AppComponent, RulesetComponent, MetadataComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    ClarityModule,
    BrowserAnimationsModule,
    UiModule,
    AgGridModule.withComponents([])
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }

