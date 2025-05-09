import { ExceptionFilter, Catch, ArgumentsHost, HttpStatus, HttpException } from "@nestjs/common";
import { Response } from "express";
import { ApiResponse } from "src/common/bases/api-reponse";

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {

    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp()
        const response = ctx.getResponse<Response>()

        let status: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR // 500 default
        let message: string = "NetWork Error"
        let errors: unknown = null

        console.log(exception);
        

        if(exception instanceof HttpException){
            status = exception.getStatus()
            const exceptionResponse = exception.getResponse()
            if(typeof exceptionResponse === 'string'){
                message = exceptionResponse
            } else if(exceptionResponse && typeof exceptionResponse === 'object'){
                const responseObj = exceptionResponse as Record<string, unknown>
                if(typeof responseObj.message === 'string'){
                    message = responseObj.message
                }else{
                    message = 'Lỗi hệ thống'
                }

                if(responseObj.errors){
                    errors = responseObj.errors
                }

                if(responseObj.status !== undefined && responseObj.code !== undefined){
                    response.status(status).json(exceptionResponse)
                    return;
                }

            }
            switch (status) {
                case HttpStatus.UNAUTHORIZED: // 401
                    message = message || "Bạn cần đăng nhập để thực hiện hành động này";
                    break;
                case HttpStatus.FORBIDDEN: // 403
                    message = message || "Bạn không có quyền thực hiện hành động này";
                    break;
                case HttpStatus.NOT_FOUND: // 404
                    message = message || "Không tìm thấy tài nguyên được yêu cầu";
                    break;
                case HttpStatus.BAD_REQUEST: // 400
                    message = message || "Dữ liệu không hợp lệ";
                    break;
                case HttpStatus.UNPROCESSABLE_ENTITY: // 400
                    message = message || "Validate dữ liệu không thành công";
                    break;
                case HttpStatus.INTERNAL_SERVER_ERROR: // 500
                    message = message || "Lỗi INTERNAL_SERVER_ERROR";
                    break;
                
                default:
                    break;
            }
        } else if(exception instanceof Error){
            console.log('Error: ', exception.message);
            console.log('stack: ', exception.stack);
            
        }else{
            message = 'Lỗi hệ thống'
        }
        const apiResponse = (errors) ? ApiResponse.error(errors, message, status) : ApiResponse.message(message, status)
        response.status(status).json(apiResponse)
    }
}