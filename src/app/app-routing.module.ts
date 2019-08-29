import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { RulesetComponent} from './views/ruleset/ruleset.component'
import { MetadataComponent} from './views/metadata/metadata.component'
import { BuildFilterComponent} from './views/build-filter/build-filter.component'

const routes: Routes = [
  {
    path: 'ruleset',
    component: RulesetComponent,
  },
  {
    path: 'metadata',
    component: MetadataComponent,
  },
  {
    path: 'bfilter',
    component: BuildFilterComponent,
  },
  {
    path: '',
    redirectTo: '/ruleset',
    pathMatch: 'full'
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
