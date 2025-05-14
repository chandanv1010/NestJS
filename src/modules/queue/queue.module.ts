import { Module } from "@nestjs/common";
import { BullModule } from "@nestjs/bull";
import { QueueService } from "./queue.service";
import { MailModule } from "../mail/mail.module";

@Module({
    imports: [
        BullModule.registerQueue({
            name: 'emails',
            defaultJobOptions: {
                attempts: 3,
                backoff: {
                    type: 'exponential', //Tăng thời gian chờ theo cấp số nhân,
                    delay: 5000, // thời gian chờ ban đầu là 5s
                },
                removeOnComplete: true,
                removeOnFail: false
            }
        }),
        MailModule
    ],
    providers: [QueueService],
    exports: [QueueService]
})

export class QueueModule {}