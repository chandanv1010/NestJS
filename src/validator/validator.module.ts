import { Module } from '@nestjs/common';
import { IsUniqueConstraint } from './is-unique.validator';

@Module({
  imports: [
    
  ],
  controllers: [],
  providers: [IsUniqueConstraint],
  exports: [IsUniqueConstraint]
})
export class ValidatorModule {}
