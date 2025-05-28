/* eslint-disable @typescript-eslint/no-unused-vars */
import { Injectable, InternalServerErrorException, UnauthorizedException, Inject, Logger, NotFoundException, BadRequestException, HttpException } from '@nestjs/common';

import { UserCatalogue } from '@prisma/client';
import { BaseService } from 'src/common/bases/base.service';
import { PrismaService } from "../../prisma/prisma.service";
import { UserCatalogueRepository } from './user.catalogue.repository';
import { UserCatalogueDto } from './dto/user.catalogue.response.dto';
import { ValidateService } from 'src/modules/validate/validate.service';
import { StoreRequest } from './dto/store.request';
import { UpdateRequest } from './dto/update.request';
import { log } from 'util';

@Injectable()
export class UserCatalogueService extends BaseService<UserCatalogueRepository, UserCatalogue, UserCatalogueDto> {
    
    private readonly serviceLogger = new Logger(UserCatalogueService.name)


    constructor(
        private readonly userCatalogueRepository: UserCatalogueRepository,
        protected readonly prismaService: PrismaService,
        private readonly validateService: ValidateService
    ){
        super(userCatalogueRepository, prismaService, UserCatalogueDto)
    }

    protected async beforeSave(id?: number, payload?: StoreRequest | UpdateRequest): Promise<this>{
        if(!payload){
            throw new BadRequestException('Dữ liệu không hợp lệ')
        }
        await this.validateService.model('userCatalogue')
                .context({id: id})
                .unique('canonical', payload.canonical, 'Canonical đã tồn tại')
                .validate()

        return Promise.resolve(this)
    }
    
}
