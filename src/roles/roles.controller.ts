import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { RolesService } from './roles.service';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@ApiTags('roles')
@Controller('roles')
@UseGuards(JwtAuthGuard, RolesGuard)
export class RolesController {
    constructor(private readonly rolesService: RolesService) { }

    @Post()
    @Roles('admin') // Somente administradores podem criar roles
    @ApiOperation({ summary: 'Criar um novo role' })
    @ApiResponse({ status: 201, description: 'O role foi criado com sucesso.' })
    @ApiResponse({ status: 403, description: 'Proibido.' })
    create(@Body() createRoleDto: CreateRoleDto) {
        return this.rolesService.create(createRoleDto);
    }

    @Get()
    @ApiOperation({ summary: 'Obter todos os roles' })
    @ApiResponse({ status: 200, description: 'Retorna todos os roles.' })
    findAll() {
        return this.rolesService.findAll();
    }

    @Get(':id')
    @ApiOperation({ summary: 'Obter um role pelo ID' })
    @ApiResponse({ status: 200, description: 'Retorna um role pelo ID.' })
    @ApiResponse({ status: 404, description: 'Role não encontrado.' })
    findOne(@Param('id') id: string) {
        return this.rolesService.findOne(+id);
    }

    @Patch(':id')
    @Roles('admin') // Somente administradores podem atualizar roles
    @ApiOperation({ summary: 'Atualizar um role' })
    @ApiResponse({ status: 200, description: 'O role foi atualizado com sucesso.' })
    @ApiResponse({ status: 404, description: 'Role não encontrado.' })
    update(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
        return this.rolesService.update(+id, updateRoleDto);
    }

    @Delete(':id')
    @Roles('admin') // Somente administradores podem excluir roles
    @ApiOperation({ summary: 'Excluir um role' })
    @ApiResponse({ status: 200, description: 'O role foi excluído com sucesso.' })
    @ApiResponse({ status: 404, description: 'Role não encontrado.' })
    remove(@Param('id') id: string) {
        return this.rolesService.remove(+id);
    }
}
