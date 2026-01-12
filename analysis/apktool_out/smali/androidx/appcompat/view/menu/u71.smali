.class public abstract Landroidx/appcompat/view/menu/u71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/il;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/u71$b;
    }
.end annotation


# instance fields
.field public a:I

.field public b:Landroidx/appcompat/view/menu/lf;

.field public c:Landroidx/appcompat/view/menu/vp0;

.field public d:Landroidx/appcompat/view/menu/lf$b;

.field public e:Landroidx/appcompat/view/menu/yl;

.field public f:I

.field public g:Z

.field public h:Landroidx/appcompat/view/menu/ml;

.field public i:Landroidx/appcompat/view/menu/ml;

.field public j:Landroidx/appcompat/view/menu/u71$b;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/lf;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroidx/appcompat/view/menu/yl;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/yl;-><init>(Landroidx/appcompat/view/menu/u71;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    const/4 v0, 0x0

    iput v0, p0, Landroidx/appcompat/view/menu/u71;->f:I

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/u71;->g:Z

    new-instance v0, Landroidx/appcompat/view/menu/ml;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/ml;-><init>(Landroidx/appcompat/view/menu/u71;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    new-instance v0, Landroidx/appcompat/view/menu/ml;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/ml;-><init>(Landroidx/appcompat/view/menu/u71;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    sget-object v0, Landroidx/appcompat/view/menu/u71$b;->m:Landroidx/appcompat/view/menu/u71$b;

    iput-object v0, p0, Landroidx/appcompat/view/menu/u71;->j:Landroidx/appcompat/view/menu/u71$b;

    iput-object p1, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    return-void
.end method


# virtual methods
.method public abstract a(Landroidx/appcompat/view/menu/il;)V
.end method

.method public final b(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;I)V
    .locals 1

    iget-object v0, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput p3, p1, Landroidx/appcompat/view/menu/ml;->f:I

    iget-object p2, p2, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final c(Landroidx/appcompat/view/menu/ml;Landroidx/appcompat/view/menu/ml;ILandroidx/appcompat/view/menu/yl;)V
    .locals 2

    iget-object v0, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p1, Landroidx/appcompat/view/menu/ml;->l:Ljava/util/List;

    iget-object v1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput p3, p1, Landroidx/appcompat/view/menu/ml;->h:I

    iput-object p4, p1, Landroidx/appcompat/view/menu/ml;->i:Landroidx/appcompat/view/menu/yl;

    iget-object p2, p2, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object p2, p4, Landroidx/appcompat/view/menu/ml;->k:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public abstract d()V
.end method

.method public abstract e()V
.end method

.method public abstract f()V
.end method

.method public final g(II)I
    .locals 1

    if-nez p2, :cond_1

    iget-object p2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v0, p2, Landroidx/appcompat/view/menu/lf;->p:I

    iget p2, p2, Landroidx/appcompat/view/menu/lf;->o:I

    invoke-static {p2, p1}, Ljava/lang/Math;->max(II)I

    move-result p2

    if-lez v0, :cond_0

    invoke-static {v0, p1}, Ljava/lang/Math;->min(II)I

    move-result p2

    :cond_0
    if-eq p2, p1, :cond_3

    goto :goto_0

    :cond_1
    iget-object p2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget v0, p2, Landroidx/appcompat/view/menu/lf;->s:I

    iget p2, p2, Landroidx/appcompat/view/menu/lf;->r:I

    invoke-static {p2, p1}, Ljava/lang/Math;->max(II)I

    move-result p2

    if-lez v0, :cond_2

    invoke-static {v0, p1}, Ljava/lang/Math;->min(II)I

    move-result p2

    :cond_2
    if-eq p2, p1, :cond_3

    :goto_0
    move p1, p2

    :cond_3
    return p1
.end method

.method public final h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;
    .locals 3

    iget-object p1, p1, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    iget-object v1, p1, Landroidx/appcompat/view/menu/jf;->b:Landroidx/appcompat/view/menu/lf;

    iget-object p1, p1, Landroidx/appcompat/view/menu/jf;->c:Landroidx/appcompat/view/menu/jf$b;

    sget-object v2, Landroidx/appcompat/view/menu/u71$a;->a:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v2, p1

    const/4 v2, 0x1

    if-eq p1, v2, :cond_5

    const/4 v2, 0x2

    if-eq p1, v2, :cond_4

    const/4 v2, 0x3

    if-eq p1, v2, :cond_3

    const/4 v2, 0x4

    if-eq p1, v2, :cond_2

    const/4 v2, 0x5

    if-eq p1, v2, :cond_1

    goto :goto_0

    :cond_1
    iget-object p1, v1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, p1, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    goto :goto_0

    :cond_2
    iget-object p1, v1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, p1, Landroidx/appcompat/view/menu/g51;->k:Landroidx/appcompat/view/menu/ml;

    goto :goto_0

    :cond_3
    iget-object p1, v1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v0, p1, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    goto :goto_0

    :cond_4
    iget-object p1, v1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, p1, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    goto :goto_0

    :cond_5
    iget-object p1, v1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v0, p1, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    :goto_0
    return-object v0
.end method

.method public final i(Landroidx/appcompat/view/menu/jf;I)Landroidx/appcompat/view/menu/ml;
    .locals 2

    iget-object p1, p1, Landroidx/appcompat/view/menu/jf;->d:Landroidx/appcompat/view/menu/jf;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    iget-object v1, p1, Landroidx/appcompat/view/menu/jf;->b:Landroidx/appcompat/view/menu/lf;

    if-nez p2, :cond_1

    iget-object p2, v1, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    goto :goto_0

    :cond_1
    iget-object p2, v1, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    :goto_0
    iget-object p1, p1, Landroidx/appcompat/view/menu/jf;->c:Landroidx/appcompat/view/menu/jf$b;

    sget-object v1, Landroidx/appcompat/view/menu/u71$a;->a:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v1, p1

    const/4 v1, 0x1

    if-eq p1, v1, :cond_3

    const/4 v1, 0x2

    if-eq p1, v1, :cond_2

    const/4 v1, 0x3

    if-eq p1, v1, :cond_3

    const/4 v1, 0x5

    if-eq p1, v1, :cond_2

    goto :goto_1

    :cond_2
    iget-object v0, p2, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    goto :goto_1

    :cond_3
    iget-object v0, p2, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    :goto_1
    return-object v0
.end method

.method public j()J
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v1, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v1, :cond_0

    iget v0, v0, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-long v0, v0

    return-wide v0

    :cond_0
    const-wide/16 v0, 0x0

    return-wide v0
.end method

.method public k()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/u71;->g:Z

    return v0
.end method

.method public final l(II)V
    .locals 7

    iget v0, p0, Landroidx/appcompat/view/menu/u71;->a:I

    if-eqz v0, :cond_8

    const/4 v1, 0x1

    if-eq v0, v1, :cond_7

    const/4 p2, 0x2

    const/high16 v2, 0x3f000000    # 0.5f

    if-eq v0, p2, :cond_4

    const/4 p2, 0x3

    if-eq v0, p2, :cond_0

    goto/16 :goto_3

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    iget-object v3, v0, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    iget-object v4, v3, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v5, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne v4, v5, :cond_1

    iget v4, v3, Landroidx/appcompat/view/menu/u71;->a:I

    if-ne v4, p2, :cond_1

    iget-object v4, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    iget-object v6, v4, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    if-ne v6, v5, :cond_1

    iget v4, v4, Landroidx/appcompat/view/menu/u71;->a:I

    if-ne v4, p2, :cond_1

    goto/16 :goto_3

    :cond_1
    if-nez p1, :cond_2

    iget-object v3, v0, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    :cond_2
    iget-object p2, v3, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean p2, p2, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz p2, :cond_9

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lf;->t()F

    move-result p2

    if-ne p1, v1, :cond_3

    iget-object p1, v3, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float p1, p1

    div-float/2addr p1, p2

    add-float/2addr p1, v2

    float-to-int p1, p1

    goto :goto_0

    :cond_3
    iget-object p1, v3, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float p1, p1

    mul-float/2addr p2, p1

    add-float/2addr p2, v2

    float-to-int p1, p2

    :goto_0
    iget-object p2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p2, p1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    goto :goto_3

    :cond_4
    iget-object p2, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object p2

    if-eqz p2, :cond_9

    if-nez p1, :cond_5

    iget-object p2, p2, Landroidx/appcompat/view/menu/lf;->e:Landroidx/appcompat/view/menu/lz;

    goto :goto_1

    :cond_5
    iget-object p2, p2, Landroidx/appcompat/view/menu/lf;->f:Landroidx/appcompat/view/menu/g51;

    :goto_1
    iget-object p2, p2, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v0, p2, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v0, :cond_9

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    if-nez p1, :cond_6

    iget v0, v0, Landroidx/appcompat/view/menu/lf;->q:F

    goto :goto_2

    :cond_6
    iget v0, v0, Landroidx/appcompat/view/menu/lf;->t:F

    :goto_2
    iget p2, p2, Landroidx/appcompat/view/menu/ml;->g:I

    int-to-float p2, p2

    mul-float/2addr p2, v0

    add-float/2addr p2, v2

    float-to-int p2, p2

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, p2, p1}, Landroidx/appcompat/view/menu/u71;->g(II)I

    move-result p1

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    goto :goto_3

    :cond_7
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget v0, v0, Landroidx/appcompat/view/menu/yl;->m:I

    invoke-virtual {p0, v0, p1}, Landroidx/appcompat/view/menu/u71;->g(II)I

    move-result p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-static {p1, p2}, Ljava/lang/Math;->min(II)I

    move-result p1

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    goto :goto_3

    :cond_8
    iget-object v0, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    invoke-virtual {p0, p2, p1}, Landroidx/appcompat/view/menu/u71;->g(II)I

    move-result p1

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/yl;->d(I)V

    :cond_9
    :goto_3
    return-void
.end method

.method public abstract m()Z
.end method

.method public n(Landroidx/appcompat/view/menu/il;Landroidx/appcompat/view/menu/jf;Landroidx/appcompat/view/menu/jf;I)V
    .locals 4

    invoke-virtual {p0, p2}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object p1

    invoke-virtual {p0, p3}, Landroidx/appcompat/view/menu/u71;->h(Landroidx/appcompat/view/menu/jf;)Landroidx/appcompat/view/menu/ml;

    move-result-object v0

    iget-boolean v1, p1, Landroidx/appcompat/view/menu/ml;->j:Z

    if-eqz v1, :cond_6

    iget-boolean v1, v0, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez v1, :cond_0

    goto :goto_1

    :cond_0
    iget v1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result p2

    add-int/2addr v1, p2

    iget p2, v0, Landroidx/appcompat/view/menu/ml;->g:I

    invoke-virtual {p3}, Landroidx/appcompat/view/menu/jf;->c()I

    move-result p3

    sub-int/2addr p2, p3

    sub-int p3, p2, v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v2, v2, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez v2, :cond_1

    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->d:Landroidx/appcompat/view/menu/lf$b;

    sget-object v3, Landroidx/appcompat/view/menu/lf$b;->o:Landroidx/appcompat/view/menu/lf$b;

    if-ne v2, v3, :cond_1

    invoke-virtual {p0, p4, p3}, Landroidx/appcompat/view/menu/u71;->l(II)V

    :cond_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget-boolean v3, v2, Landroidx/appcompat/view/menu/ml;->j:Z

    if-nez v3, :cond_2

    return-void

    :cond_2
    iget v2, v2, Landroidx/appcompat/view/menu/ml;->g:I

    if-ne v2, p3, :cond_3

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/ml;->d(I)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/ml;->d(I)V

    return-void

    :cond_3
    iget-object p3, p0, Landroidx/appcompat/view/menu/u71;->b:Landroidx/appcompat/view/menu/lf;

    if-nez p4, :cond_4

    invoke-virtual {p3}, Landroidx/appcompat/view/menu/lf;->w()F

    move-result p3

    goto :goto_0

    :cond_4
    invoke-virtual {p3}, Landroidx/appcompat/view/menu/lf;->K()F

    move-result p3

    :goto_0
    const/high16 p4, 0x3f000000    # 0.5f

    if-ne p1, v0, :cond_5

    iget v1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    iget p2, v0, Landroidx/appcompat/view/menu/ml;->g:I

    move p3, p4

    :cond_5
    sub-int/2addr p2, v1

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget p1, p1, Landroidx/appcompat/view/menu/ml;->g:I

    sub-int/2addr p2, p1

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    int-to-float v0, v1

    add-float/2addr v0, p4

    int-to-float p2, p2

    mul-float/2addr p2, p3

    add-float/2addr v0, p2

    float-to-int p2, v0

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/ml;->d(I)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/u71;->i:Landroidx/appcompat/view/menu/ml;

    iget-object p2, p0, Landroidx/appcompat/view/menu/u71;->h:Landroidx/appcompat/view/menu/ml;

    iget p2, p2, Landroidx/appcompat/view/menu/ml;->g:I

    iget-object p3, p0, Landroidx/appcompat/view/menu/u71;->e:Landroidx/appcompat/view/menu/yl;

    iget p3, p3, Landroidx/appcompat/view/menu/ml;->g:I

    add-int/2addr p2, p3

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/ml;->d(I)V

    :cond_6
    :goto_1
    return-void
.end method

.method public o(Landroidx/appcompat/view/menu/il;)V
    .locals 0

    return-void
.end method

.method public p(Landroidx/appcompat/view/menu/il;)V
    .locals 0

    return-void
.end method
