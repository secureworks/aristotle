import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { RulesetComponent} from './views/ruleset/ruleset.component'
import { MetadataComponent} from './views/metadata/metadata.component'

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
