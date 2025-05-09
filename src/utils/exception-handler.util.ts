import {Logger } from "@nestjs/common";

export class ExceptionHandler {


    static error(
        error: unknown,
        logger: Logger
    ): never{
        const err = error as Error
        logger.error(`Lỗi: ${err.message}`, err.stack)
        throw error;

    }

}