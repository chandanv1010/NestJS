import { Module } from '@nestjs/common';
import { UserRepository } from './user.repository';
import { UserService } from './user.service';

@Module({
  imports: [
    
  ],
  controllers: [],
  providers: [UserRepository, UserService],
  exports: [UserRepository, UserService]
})
export class UserModule {}
