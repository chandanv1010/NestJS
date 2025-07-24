import { Module } from '@nestjs/common';
import { UserCatalogueRepository } from './user.catalogue.repository';
import { UserCatalogueService } from './user.catalogue.service';
import { UserCatalogueController } from './user.catalogue.controller';
import { ValidateModule } from 'src/modules/validate/validate.module';
import { DataTransformer } from 'src/common/bases/data.transform';

@Module({
  imports: [
    ValidateModule
  ],
  controllers: [UserCatalogueController],
  providers: [UserCatalogueRepository, UserCatalogueService, DataTransformer],
  exports: [UserCatalogueRepository, UserCatalogueService, DataTransformer]
})
export class UserCatalogueModule {}
