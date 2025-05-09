/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './modules/auth/auth.module';
import { UserModule } from './modules/user/user.module';
import { CacheModule } from '@nestjs/cache-manager';
import { createKeyv } from '@keyv/redis';
import { Keyv } from 'keyv';
import { CacheableMemory } from 'cacheable';
import { PrismaModule } from './modules/prisma/prisma.module';

@Module({
  imports: [
    AuthModule,
    UserModule,
    PrismaModule,
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: () => {
        return {
          stores: [
            new Keyv({
              store: new CacheableMemory({ ttl: 60000, lruSize: 5000 }),
              namespace: 'nestjs-memory-cache'
            }),
            createKeyv('redis://localhost:6379/1', {
              namespace: 'nestjs_newbie'
            }),
          ],
        };
      }
    })
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
