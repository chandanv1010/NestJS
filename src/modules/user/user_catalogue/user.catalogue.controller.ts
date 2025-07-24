/* eslint-disable @typescript-eslint/no-unused-vars */
import { Body, Controller, HttpStatus, Post, Req, HttpCode, Get, UseGuards, Res, Param, Put, Delete, Patch } from '@nestjs/common';
import { ValidationPipe } from 'src/pipes/validation.pipe';

import { ApiResponse, TApiReponse } from 'src/common/bases/api-reponse';
import { Request } from 'express';
import { common } from 'src/config/constant';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { GuardType } from 'src/common/guards/jwt-auth.guard'; 
import { StoreRequest } from './dto/store.request';
import { UpdateRequest, UpdatePatchRequest } from './dto/update.request';
import { UserCatalogueService } from './user.catalogue.service';
import { Logger } from "@nestjs/common";
import { BaseController } from 'src/common/bases/base.controller';
import { UserCatalogue } from '@prisma/client';
import { UserCatalogueDTO } from './dto/user.catalogue.response.dto';
import { TResult } from 'src/common/bases/base.service';
import { DataTransformer } from 'src/common/bases/data.transform';
import { TModelOrPaginate } from 'src/common/bases/base.interface';
import { IPaginateResult } from 'src/classes/query-builder.class';

const GUARD = common.admin

/**
 * - paginate - phân trang
 * - batchStore
 * - batchUdate [ patch ]
 * - attach
 * - detach
 * 
 * 
 */

@Controller('v1/user_catalogues')
export class UserCatalogueController extends BaseController<
    UserCatalogue, 
    UserCatalogueService
> {
    private readonly controllerLogger = new Logger(BaseController.name)
   

    constructor(
        private readonly userCatalogueService: UserCatalogueService,
        private readonly transformer: DataTransformer<UserCatalogue, UserCatalogueDTO>
    ) {
        super(userCatalogueService);
    }

    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    @Post()
    @HttpCode(HttpStatus.CREATED)
    async store(
         @Body(new ValidationPipe()) storeRequest: StoreRequest,
    ) : Promise<TApiReponse<UserCatalogueDTO>> {

        const data: UserCatalogue = await this.userCatalogueService.save<StoreRequest>(storeRequest)
        return ApiResponse.ok(
            this.transformer.transformSingle(data, UserCatalogueDTO),
            'Success', 
            HttpStatus.CREATED
        )      
    }

    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    @Put(':id')
    @HttpCode(HttpStatus.OK)
    async update(
        @Body(new ValidationPipe()) updateRequest: UpdateRequest,
        @Param('id') id: number,
        @Req() req: Request
    ): Promise<TApiReponse<UserCatalogueDTO>>{
        const data: UserCatalogue = await this.userCatalogueService.save(updateRequest, id)
        return ApiResponse.ok(
            this.transformer.transformSingle(data, UserCatalogueDTO),
            'Success', 
            HttpStatus.OK
        )
    }

    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    @Patch(':id')
    @HttpCode(HttpStatus.OK)
    async updatePatch(
        @Body(new ValidationPipe()) updateRequest: UpdatePatchRequest,
        @Param('id') id: number,
        @Req() req: Request
    ): Promise<TApiReponse<UserCatalogueDTO>>{
        const data: TResult<UserCatalogue> = await this.userCatalogueService.save(updateRequest, id)
        return ApiResponse.ok(
            this.transformer.transformSingle(data, UserCatalogueDTO), 
            'Success', 
            HttpStatus.OK
        )
    }

    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    @Delete(':id')
    @HttpCode(HttpStatus.OK)
    async destroy(
        @Param('id') id: number
    ): Promise<ApiResponse>{
        await this.userCatalogueService.destroy(id)
        return ApiResponse.message('Xóa bản ghi thành công', HttpStatus.OK)

    }

    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    @Get(':id')
    @HttpCode(HttpStatus.OK)
    async show(
        @Param('id') id: number
    ): Promise<TApiReponse<UserCatalogueDTO>>{
        const data: UserCatalogue = await this.userCatalogueService.show(id)
        return ApiResponse.ok(
            this.transformer.transformSingle(data, UserCatalogueDTO), 
            'Success', 
            HttpStatus.OK
        )

    }

    @GuardType(GUARD)
    @UseGuards(JwtAuthGuard)
    @Get()
    @HttpCode(HttpStatus.OK)
    async paginate(
         @Req() req: Request
    ): Promise<TApiReponse<TModelOrPaginate<UserCatalogue>>>{
        const data: UserCatalogue[] | IPaginateResult<UserCatalogue> = await this.userCatalogueService.paginate(req)
        let dataTransform
        if(Array.isArray(data)){
            dataTransform = this.transformer.transformArray(data, UserCatalogueDTO)
        }else{
            dataTransform = this.transformer.transformPaginated(data, UserCatalogueDTO)
        }

        return ApiResponse.ok(
            dataTransform, 
            'Success',
             HttpStatus.OK
        )

    }
    
}
