import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { PermissionsService } from './permissions.service';
import { CreatePermissionDto } from './dto/create-permission.dto';
import { UpdatePermissionDto } from './dto/update-permission.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@ApiTags('permissions')
@Controller('permissions')
@UseGuards(JwtAuthGuard, RolesGuard)
export class PermissionsController {
    constructor(private readonly permissionsService: PermissionsService) { }

    @Post()
    @Roles('admin') // Somente administradores podem criar permissões
    @ApiOperation({ summary: 'Criar uma nova permissão' })
    @ApiResponse({ status: 201, description: 'A permissão foi criada com sucesso.' })
    @ApiResponse({ status: 403, description: 'Proibido.' })
    create(@Body() createPermissionDto: CreatePermissionDto) {
        return this.permissionsService.create(createPermissionDto);
    }

    @Get()
    @ApiOperation({ summary: 'Obter todas as permissões' })
    @ApiResponse({ status: 200, description: 'Retorna todas as permissões.' })
    findAll() {
        return this.permissionsService.findAll();
    }

    @Get(':id')
    @ApiOperation({ summary: 'Obter uma permissão pelo ID' })
    @ApiResponse({ status: 200, description: 'Retorna uma permissão pelo ID.' })
    @ApiResponse({ status: 404, description: 'Permissão não encontrada.' })
    findOne(@Param('id') id: string) {
        return this.permissionsService.findOne(+id);
    }

    @Patch(':id')
    @Roles('admin') // Somente administradores podem atualizar permissões
    @ApiOperation({ summary: 'Atualizar uma permissão' })
    @ApiResponse({ status: 200, description: 'A permissão foi atualizada com sucesso.' })
    @ApiResponse({ status: 404, description: 'Permissão não encontrada.' })
    update(@Param('id') id: string, @Body() updatePermissionDto: UpdatePermissionDto) {
        return this.permissionsService.update(+id, updatePermissionDto);
    }

    @Delete(':id')
    @Roles('admin') // Somente administradores podem excluir permissões
    @ApiOperation({ summary: 'Excluir uma permissão' })
    @ApiResponse({ status: 200, description: 'A permissão foi excluída com sucesso.' })
    @ApiResponse({ status: 404, description: 'Permissão não encontrada.' })
    remove(@Param('id') id: string) {
        return this.permissionsService.remove(+id);
    }
}
