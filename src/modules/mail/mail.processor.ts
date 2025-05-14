import { Process, Processor } from "@nestjs/bull";
import { Job } from "bull";
import { Logger } from "@nestjs/common";
import { MailService } from "./mail.service";

@Processor('emails')
export class EmailProcessor {
    private readonly logger = new Logger(EmailProcessor.name)

    constructor(
        private readonly mailService: MailService
    ){}

    @Process('send-reset-email')
    async handleSendResetEmail(job: Job<{email: string, token: string}>): Promise<void>{
        this.logger.log(`Bắt đầu xử lý email đặt lại mật khẩu cho job: ${job.data.email}`)
        try {
            await this.mailService.sendForgotResetEmail(job.data.email, job.data.token)

        } catch (error) {
            this.logger.error(`Lỗi khi gửi email đặt lại mật khẩu cho ${job.data.email}: ${error instanceof Error ? error.message : 'Không xác định'}`)
            throw error
        }
    } 
}