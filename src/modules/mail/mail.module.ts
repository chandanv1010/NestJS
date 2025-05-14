import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { ConfigModule } from '@nestjs/config';
import { EmailProcessor } from './mail.processor';

@Module({
  imports: [
    ConfigModule
  ],
  controllers: [],
  providers: [MailService, EmailProcessor],
  exports: [MailService]
})
export class MailModule {}
