.class public Landroidx/appcompat/view/menu/g51;
.super Landroidx/appcompat/view/menu/u71;
.source "SourceFile"


# instance fields
.field public k:Landroidx/appcompat/view/menu/ml;

.field public l:Landroidx/appcompat/view/menu/yl;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/lf;)V
    .locals 2

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/u71;-><init>(Landroidx/appcompat/view/menu/lf;)V

    new-instance p1, Landroidx/appcompat/view/menu/ml;

    invoke-direct {p1, p0}, Landroidx/appcompat/view/menu/ml;-><init>(Landroidx/appcompat/view/menu/u71;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/appcompat/view/menu/g51;->l:Landroidx/appcompat/view/menu/yl;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    sget-object v1, Landroidx/appcompat/view/menu/ml$a;->r:Landroidx/appcompat/view/menu/ml$a;

    iput-object v1, v0, Landroidx/appcompat/view/menu/ml;->e:Landroidx/appcompat/view/menu/ml$a;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    sget-object v1, Landroidx/appcompat/view/menu/ml$a;->s:Landroidx/appcompat/view/menu/ml$a;

    iput-object v1, v0, Landroidx/appcompat/view/menu/ml;->e:Landroidx/appcompat/view/menu/ml$a;

    sget-object v0, Landroidx/appcompat/view/menu/ml$a;->t:Landroidx/appcompat/view/menu/ml$a;

    iput-object v0, p1, Landroidx/appcompat/view/menu/ml;->e:Landroidx/appcompat/view/menu/ml$a;

    const/4 p1, 0x1

    iput p1, p0, Landroidx/appcompat/view/menu/u71;->f:I

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/il;)V
    .locals 6

    sget-object v0, Landroidx/appcompat/view/menu/g51$a;->a:[I

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->j:Landroidx/appcompat/view/menu/u71$b;

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x3

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eq v0, v3, :cond_2

    if-eq v0, v2, :cond_1

    if-eq v0, v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v0, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->E:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p0, p1, v1, v0, v3}, Landroidx/appcompat/view/menu/u71;->n(Landroidx/appcompat/view/menu/il;Landroidx/appcompat/view/menu/jf;Landroidx/appcompat/view/menu/jf;I)V

    return-void

    :cond_1
    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/u71;->o(Landroidx/appcompat/view/menu/il;)V

    goto :goto_0

    :cond_2
    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/u71;->p(Landroidx/appcompat/view/menu/il;)V

    :goto_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v0, p1, Landroidx/appcompat/view/menu/ml;->c:Z

    const/high16 v4, 0x3f000000    # 0.5f

    const/4 v5, 0x0

    if-eqz v0, :cond_8

    iget-boolean p1, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez p1, :cond_8

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v0, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne p1, v0, :cond_8

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v0, p1, Landroidx/appcompat/view/menu/lf;->m:I

    if-eq v0, v2, :cond_7

    if-eq v0, v1, :cond_3

    goto :goto_4

    :cond_3
    iget-object v0, p1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v0, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v0, :cond_8

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->u()I

    move-result p1

    const/4 v0, -0x1

    if-eq p1, v0, :cond_6

    if-eqz p1, :cond_5

    if-eq p1, v3, :cond_4

    move p1, v5

    goto :goto_3

    :cond_4
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, p1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float v0, v0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->t()F

    move-result p1

    :goto_1
    div-float/2addr v0, p1

    :goto_2
    add-float/2addr v0, v4

    float-to-int p1, v0

    goto :goto_3

    :cond_5
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, p1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float v0, v0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->t()F

    move-result p1

    mul-float/2addr v0, p1

    goto :goto_2

    :cond_6
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, p1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float v0, v0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->t()F

    move-result p1

    goto :goto_1

    :goto_3
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    goto :goto_4

    :cond_7
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object p1

    if-eqz p1, :cond_8

    iget-object p1, p1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object p1, p1, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v0, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v0, :cond_8

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v0, v0, Landroidx/appcompat/view/menu/lf;->t:F

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float p1, p1

    mul-float/2addr p1, v0

    add-float/2addr p1, v4

    float-to-int p1, p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    :cond_8
    :goto_4
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-boolean v0, p1, Landroidx/appcompat/view/menu/ml;->c:Z

    if-eqz v0, :cond_10

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-boolean v1, v0, Landroidx/appcompat/view/menu/ml;->c:Z

    if-nez v1, :cond_9

    goto/16 :goto_6

    :cond_9
    iget-boolean p1, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz p1, :cond_a

    iget-boolean p1, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz p1, :cond_a

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean p1, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz p1, :cond_a

    return-void

    :cond_a
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean p1, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez p1, :cond_b

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v0, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne p1, v0, :cond_b

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v0, p1, Landroidx/appcompat/view/menu/lf;->l:I

    if-nez v0, :cond_b

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->X()Z

    move-result p1

    if-nez p1, :cond_b

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/ml;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ml;

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget v2, v1, Landroidx/appcompat/view/menu/ml;->f:I

    add-int/2addr p1, v2

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget v2, v2, Landroidx/appcompat/view/menu/ml;->f:I

    add-int/2addr v0, v2

    sub-int v2, v0, p1

    invoke-virtual {v1, p1}, Landroidx/appcompat/view/menu/ml;->d(I)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/ml;->d(I)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p1, v2}, Landroidx/appcompat/view/menu/yl;->d(I)V

    return-void

    :cond_b
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean p1, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez p1, :cond_d

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v0, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne p1, v0, :cond_d

    iget p1, p0, Landroidx/appcompat/view/menu/u71;->a:I

    if-ne p1, v3, :cond_d

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_d

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_d

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/ml;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ml;

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget v1, v1, Landroidx/appcompat/view/menu/ml;->f:I

    add-int/2addr p1, v1

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget v1, v1, Landroidx/appcompat/view/menu/ml;->f:I

    add-int/2addr v0, v1

    sub-int/2addr v0, p1

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v1, p1, Landroidx/appcompat/view/menu/yl;->m:I

    if-ge v0, v1, :cond_c

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/yl;->d(I)V

    goto :goto_5

    :cond_c
    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    :cond_d
    :goto_5
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean p1, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez p1, :cond_e

    return-void

    :cond_e
    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_10

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_10

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/ml;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ml;

    iget v1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget v2, v2, Landroidx/appcompat/view/menu/ml;->f:I

    add-int/2addr v1, v2

    iget v2, v0, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object v3, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget v3, v3, Landroidx/appcompat/view/menu/ml;->f:I

    add-int/2addr v2, v3

    iget-object v3, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/lf;->K()F

    move-result v3

    if-ne p1, v0, :cond_f

    iget v1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    iget v2, v0, Landroidx/appcompat/view/menu/ml;->g:I

    move v3, v4

    :cond_f
    sub-int/2addr v2, v1

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    sub-int/2addr v2, p1

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    int-to-float v0, v1

    add-float/2addr v0, v4

    int-to-float v1, v2

    mul-float/2addr v1, v3

    add-float/2addr v0, v1

    float-to-int v0, v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/ml;->d(I)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v1, v1, Landroidx/appcompat/view/menu/ml;->g:I

    add-int/2addr v0, v1

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/ml;->d(I)V

    :cond_10
    :goto_6
    return-void
.end method

.method public d()V
    .locals 10

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-boolean v1, v0, Landroidx/appcompat/view/menu/lf;->a:Z

    if-eqz v1, :cond_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->v()I

    move-result v0

    invoke-virtual {v1, v0}, Landroidx/appcompat/view/menu/yl;->d(I)V

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v0, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez v0, :cond_3

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->M()Landroidx/appcompat/view/menu/lf$b;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance v0, Landroidx/appcompat/view/menu/c8;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/c8;-><init>(Landroidx/appcompat/view/menu/u71;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/g51;->l:Landroidx/appcompat/view/menu/yl;

    :cond_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-eq v0, v1, :cond_4

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->p:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v1, :cond_2

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->M()Landroidx/appcompat/view/menu/lf$b;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/lf$b;->m:Landroidx/appcompat/view/menu/lf$b;

    if-ne v1, v2, :cond_2

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->v()I

    move-result v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    sub-int/2addr v1, v2

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->E:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    sub-int/2addr v1, v2

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v3, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v3, v3, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v4, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v4, v4, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {v4}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v4

    invoke-virtual {p0, v2, v3, v4}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v3, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v3, v3, Landroidx/appcompat/view/menu/lf;->E:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v3

    neg-int v3, v3

    invoke-virtual {p0, v2, v0, v3}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    return-void

    :cond_2
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->m:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v1, :cond_4

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lf;->v()I

    move-result v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    goto :goto_0

    :cond_3
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->p:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v1, :cond_4

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->M()Landroidx/appcompat/view/menu/lf$b;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/lf$b;->m:Landroidx/appcompat/view/menu/lf$b;

    if-ne v1, v2, :cond_4

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v2, v2, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v3, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v3, v3, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v3

    invoke-virtual {p0, v1, v2, v3}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->E:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    neg-int v2, v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    return-void

    :cond_4
    :goto_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v1, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    const/4 v2, 0x0

    const/4 v3, 0x4

    const/4 v4, 0x2

    const/4 v5, 0x1

    const/4 v6, 0x3

    if-eqz v1, :cond_d

    iget-object v7, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-boolean v8, v7, Landroidx/appcompat/view/menu/lf;->a:Z

    if-eqz v8, :cond_d

    iget-object v0, v7, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v1, v0, v4

    iget-object v8, v1, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-eqz v8, :cond_8

    aget-object v9, v0, v6

    iget-object v9, v9, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-eqz v9, :cond_8

    invoke-virtual {v7}, Landroidx/appcompat/view/menu/lf;->X()Z

    move-result v0

    if-eqz v0, :cond_5

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v1, v1, v4

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v1

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v1, v1, v6

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v1

    neg-int v1, v1

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    goto :goto_1

    :cond_5
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v0, v0, v4

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_6

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v2, v2, v4

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    :cond_6
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v0, v0, v6

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_7

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v2, v2, v6

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    neg-int v2, v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    :cond_7
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iput-boolean v5, v0, Landroidx/appcompat/view/menu/ml;->b:Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iput-boolean v5, v0, Landroidx/appcompat/view/menu/ml;->b:Z

    :goto_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1c

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lf;->n()I

    move-result v2

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    goto/16 :goto_5

    :cond_8
    if-eqz v8, :cond_9

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_1c

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v2, v2, v4

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v2, v2, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1c

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lf;->n()I

    move-result v2

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    goto/16 :goto_5

    :cond_9
    aget-object v1, v0, v6

    iget-object v4, v1, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-eqz v4, :cond_b

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_a

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v2, v2, v6

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    neg-int v2, v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v2, v2, Landroidx/appcompat/view/menu/ml;->g:I

    neg-int v2, v2

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    :cond_a
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1c

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lf;->n()I

    move-result v2

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    goto/16 :goto_5

    :cond_b
    aget-object v0, v0, v3

    iget-object v1, v0, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-eqz v1, :cond_c

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_1c

    iget-object v1, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lf;->n()I

    move-result v2

    neg-int v2, v2

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v2, v2, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    goto/16 :goto_5

    :cond_c
    instance-of v0, v7, Landroidx/appcompat/view/menu/fz;

    if-nez v0, :cond_1c

    invoke-virtual {v7}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    if-eqz v0, :cond_1c

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    sget-object v1, Landroidx/appcompat/view/menu/jf$b;->s:Landroidx/appcompat/view/menu/jf$b;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/lf;->m(Landroidx/appcompat/view/menu/jf$b;)Landroidx/appcompat/view/menu/jf;

    move-result-object v0

    iget-object v0, v0, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-nez v0, :cond_1c

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lf;->R()I

    move-result v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v2, v2, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1c

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lf;->n()I

    move-result v2

    invoke-virtual {p0, v0, v1, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    goto/16 :goto_5

    :cond_d
    if-nez v1, :cond_12

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v7, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne v1, v7, :cond_12

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v1, v0, Landroidx/appcompat/view/menu/lf;->m:I

    if-eq v1, v4, :cond_10

    if-eq v1, v6, :cond_e

    goto :goto_2

    :cond_e
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->X()Z

    move-result v0

    if-nez v0, :cond_13

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v1, v0, Landroidx/appcompat/view/menu/lf;->l:I

    if-ne v1, v6, :cond_f

    goto :goto_2

    :cond_f
    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v1, v1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iput-boolean v5, v0, Landroidx/appcompat/view/menu/ml;->b:Z

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_10
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    if-nez v0, :cond_11

    goto :goto_2

    :cond_11
    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v1, v1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iput-boolean v5, v0, Landroidx/appcompat/view/menu/ml;->b:Z

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_12
    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/ml;->b(Landroidx/appcompat/view/menu/il;)V

    :cond_13
    :goto_2
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v7, v1, v4

    iget-object v8, v7, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-eqz v8, :cond_15

    aget-object v9, v1, v6

    iget-object v9, v9, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-eqz v9, :cond_15

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->X()Z

    move-result v0

    if-eqz v0, :cond_14

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v1, v1, v4

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v1

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v1, v1, v6

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v1

    neg-int v1, v1

    iput v1, v0, Landroidx/appcompat/view/menu/ml;->f:I

    goto :goto_3

    :cond_14
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v0, v0, v4

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v1, v1, v6

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v1

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/ml;->b(Landroidx/appcompat/view/menu/il;)V

    invoke-virtual {v1, p0}, Landroidx/appcompat/view/menu/ml;->b(Landroidx/appcompat/view/menu/il;)V

    sget-object v0, Landroidx/appcompat/view/menu/u71$b;->p:Landroidx/appcompat/view/menu/u71$b;

    iput-object v0, p0, Landroidx/appcompat/view/menu/u71;->j:Landroidx/appcompat/view/menu/u71$b;

    :goto_3
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1b

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/g51;->l:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v5, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    goto/16 :goto_4

    :cond_15
    const/4 v9, 0x0

    if-eqz v8, :cond_17

    invoke-virtual {p0, v7}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_1b

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v2, v2, v4

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v5, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_16

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/g51;->l:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v5, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    :cond_16
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v1, :cond_1b

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->t()F

    move-result v0

    cmpl-float v0, v0, v9

    if-lez v0, :cond_1b

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v2, v0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    if-ne v2, v1, :cond_1b

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v1, v1, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iput-object p0, v0, Landroidx/appcompat/view/menu/ml;->a:Landroidx/appcompat/view/menu/il;

    goto/16 :goto_4

    :cond_17
    aget-object v4, v1, v6

    iget-object v7, v4, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    const/4 v8, -0x1

    if-eqz v7, :cond_18

    invoke-virtual {p0, v4}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_1b

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v2, v2, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    aget-object v2, v2, v6

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result v2

    neg-int v2, v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v8, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1b

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/g51;->l:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v5, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    goto/16 :goto_4

    :cond_18
    aget-object v1, v1, v3

    iget-object v3, v1, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    if-eqz v3, :cond_19

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    if-eqz v0, :cond_1b

    iget-object v1, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/g51;->l:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v8, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v5, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    goto :goto_4

    :cond_19
    instance-of v1, v0, Landroidx/appcompat/view/menu/fz;

    if-nez v1, :cond_1b

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    if-eqz v0, :cond_1b

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lf;->R()I

    move-result v2

    invoke-virtual {p0, v1, v0, v2}, Landroidx/appcompat/view/menu/u71;->b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v5, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->S()Z

    move-result v0

    if-eqz v0, :cond_1a

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-object v2, p0, Landroidx/appcompat/view/menu/g51;->l:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, v0, v1, v5, v2}, Landroidx/appcompat/view/menu/u71;->c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V

    :cond_1a
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v1, :cond_1b

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->t()F

    move-result v0

    cmpl-float v0, v0, v9

    if-lez v0, :cond_1b

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v2, v0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    if-ne v2, v1, :cond_1b

    iget-object v0, v0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v1, v1, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iput-object p0, v0, Landroidx/appcompat/view/menu/ml;->a:Landroidx/appcompat/view/menu/il;

    :cond_1b
    :goto_4
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-object v0, v0, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    if-nez v0, :cond_1c

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iput-boolean v5, v0, Landroidx/appcompat/view/menu/ml;->c:Z

    :cond_1c
    :goto_5
    return-void
.end method

.method public e()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget-boolean v1, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v1, :cond_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {v1, v0}, Landroidx/appcompat/view/menu/lf;->G0(I)V

    :cond_0
    return-void
.end method

.method public f()V
    .locals 1

    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/appcompat/view/menu/u71;->c:Landroidx/appcompat/view/menu/vp0;

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ml;->c()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ml;->c()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ml;->c()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ml;->c()V

    const/4 v0, 0x0

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/u71;->g:Z

    return-void
.end method

.method public m()Z
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    const/4 v2, 0x1

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v0, v0, Landroidx/appcompat/view/menu/lf;->m:I

    if-nez v0, :cond_0

    return v2

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    return v2
.end method

.method public q()V
    .locals 2

    const/4 v0, 0x0

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/u71;->g:Z

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/ml;->c()V

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iput-boolean v0, v1, Landroidx/appcompat/view/menu/ml;->j:Z

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/ml;->c()V

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iput-boolean v0, v1, Landroidx/appcompat/view/menu/ml;->j:Z

    iget-object v1, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/ml;->c()V

    iget-object v1, p0, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    iput-boolean v0, v1, Landroidx/appcompat/view/menu/ml;->j:Z

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iput-boolean v0, v1, Landroidx/appcompat/view/menu/ml;->j:Z

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "VerticalRun "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lf;->r()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
