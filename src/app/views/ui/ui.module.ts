import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LayoutComponent } from './layout/layout.component';
import { HeaderComponent } from './header/header.component';
import { MainComponent } from './main/main.component';
import { SidebarComponent } from './sidebar/sidebar.component';
import { ClarityModule } from '@clr/angular';
import { RouterModule } from '@angular/router';
import { AgGridModule } from 'ag-grid-angular';


@NgModule({
  declarations: [LayoutComponent, HeaderComponent, MainComponent, SidebarComponent],
  imports: [
    CommonModule,
    ClarityModule,
    RouterModule,
    AgGridModule.withComponents([])
  ],
  exports: [
    LayoutComponent
  ]
})
export class UiModule { }
