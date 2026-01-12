.class public Landroidx/appcompat/view/menu/my;
.super Landroidx/appcompat/view/menu/u71;
.source "SourceFile"


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/lf;)V
    .locals 1

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/u71;-><init>(Landroidx/appcompat/view/menu/lf;)V

    iget-object v0, p1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lz;->f()V

    iget-object v0, p1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/g51;->f()V

    check-cast p1, Landroidx/appcompat/view/menu/ly;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ly;->K0()I

    move-result p1

    iput p1, p0, Landroidx/appcompat/view/menu/u71;->f:I

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/il;)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-boolean v0, p1, Landroidx/appcompat/view/menu/ml;->c:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-boolean v0, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v0, :cond_1

    return-void

    :cond_1
    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/ml;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    check-cast v0, Landroidx/appcompat/view/menu/ly;

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float p1, p1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ly;->N0()F

    move-result v0

    mul-float/2addr p1, v0

    const/high16 v0, 0x3f000000    # 0.5f

    add-float/2addr p1, v0

    float-to-int p1, p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/ml;->d(I)V

    return-void
.end method

.method public d()V
    .locals 5

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    check-cast v0, Landroidx/appcompat/view/menu/ly;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ly;->L0()I

    move-result v1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ly;->M0()I

    move-result v2

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ly;->N0()F

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ly;->K0()I

    move-result v0

    const/4 v3, -0x1

    const/4 v4, 0x1

    if-ne v0, v4, :cond_2

    if-eq v1, v3, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v2, v2, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    goto :goto_0

    :cond_0
    if-eq v2, v3, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v1, v1, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    neg-int v1, v2

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    goto :goto_0

    :cond_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iput-boolean v4, v0, Landroidx/appcompat/view/menu/ml;->b:Z

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v1, v1, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/my;->q(Landroidx/appcompat/view/menu/ml;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/my;->q(Landroidx/appcompat/view/menu/ml;)V

    goto/16 :goto_2

    :cond_2
    if-eq v1, v3, :cond_3

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v2, v2, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    goto :goto_1

    :cond_3
    if-eq v2, v3, :cond_4

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v1, v1, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    neg-int v1, v2

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    goto :goto_1

    :cond_4
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iput-boolean v4, v0, Landroidx/appcompat/view/menu/ml;->b:Z

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v1, v1, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/my;->q(Landroidx/appcompat/view/menu/ml;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/my;->q(Landroidx/appcompat/view/menu/ml;)V

    :goto_2
    return-void
.end method

.method public e()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    check-cast v0, Landroidx/appcompat/view/menu/ly;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ly;->K0()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget v1, v1, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/lf;->F0(I)V

    goto :goto_0

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget v1, v1, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/lf;->G0(I)V

    :goto_0
    return-void
.end method

.method public f()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ml;->c()V

    return-void
.end method

.method public m()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final q(Landroidx/appcompat/view/menu/ml;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {p1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method
