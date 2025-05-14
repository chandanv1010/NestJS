/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './modules/auth/auth.module';
import { UserModule } from './modules/user/user.module';
import { CacheModule } from '@nestjs/cache-manager';
import { createKeyv } from '@keyv/redis';
import { PrismaModule } from './modules/prisma/prisma.module';
import { MailModule } from './modules/mail/mail.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BullModule } from '@nestjs/bull';

@Module({
  imports: [
    AuthModule,
    UserModule,
    PrismaModule,
    MailModule,
    ConfigModule.forRoot({
        isGlobal: true
    }),
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: () => {
        return {
          stores: [
            // new Keyv({
            //   store: new CacheableMemory({ ttl: 60000, lruSize: 5000 }),
            //   namespace: 'nestjs-memory-cache'
            // }),
            createKeyv('redis://localhost:6379/2', {
              namespace: 'nestjs_newbie'
            }),
          ],
        };
      }
    }),
    BullModule.forRootAsync({
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
            redis: {
                host: configService.get('REDIS_HOST', '127.0.0.1'),
                port: configService.get('REDIS_PORT', 6379),
                password: configService.get('REDIS_PASS', '')
            },
            defaultJobOptions: {
                attempts: 3,
                removeOnComplete: true
            }
        }),
        inject: [ConfigService]
    })
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
