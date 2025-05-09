import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { GlobalExceptionFilter } from './exceptions/global-exception.filter';
import * as cookieParser from 'cookie-parser'

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    app.useGlobalFilters(new GlobalExceptionFilter())  
    app.enableCors({
        credentials: true,
        origin: process.env.FRONTEND_URL,
    })
    app.use(cookieParser())
  await app.listen(process.env.PORT ?? 3000);
}
// eslint-disable-next-line @typescript-eslint/no-floating-promises
bootstrap();
