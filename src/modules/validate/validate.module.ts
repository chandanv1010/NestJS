import { Module } from '@nestjs/common';
import { ValidateService } from './validate.service';

@Module({
  imports: [
    
  ],
  controllers: [],
  providers: [ValidateService],
  exports: [ValidateService]
})
export class ValidateModule {}
