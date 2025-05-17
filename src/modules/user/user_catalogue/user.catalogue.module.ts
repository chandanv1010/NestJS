import { Module } from '@nestjs/common';
import { UserCatalogueRepository } from './user.catalogue.repository';
import { UserCatalogueService } from './user.catalogue.service';
import { UserCatalogueController } from './user.catalogue.controller';

@Module({
  imports: [
    
  ],
  controllers: [UserCatalogueController],
  providers: [UserCatalogueRepository, UserCatalogueService],
  exports: [UserCatalogueRepository, UserCatalogueService]
})
export class UserCatalogueModule {}
