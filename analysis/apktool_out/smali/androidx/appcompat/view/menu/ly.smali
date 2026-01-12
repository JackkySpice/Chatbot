.class public Landroidx/appcompat/view/menu/ly;
.super Landroidx/appcompat/view/menu/lf;
.source "SourceFile"


# instance fields
.field public A0:I

.field public B0:I

.field public w0:F

.field public x0:I

.field public y0:I

.field public z0:Landroidx/appcompat/view/menu/jf;


# direct methods
.method public constructor <init>()V
    .locals 4

    invoke-direct {p0}, Landroidx/appcompat/view/menu/lf;-><init>()V

    const/high16 v0, -0x40800000    # -1.0f

    iput v0, p0, Landroidx/appcompat/view/menu/ly;->w0:F

    const/4 v0, -0x1

    iput v0, p0, Landroidx/appcompat/view/menu/ly;->x0:I

    iput v0, p0, Landroidx/appcompat/view/menu/ly;->y0:I

    iget-object v0, p0, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    iput-object v0, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    const/4 v0, 0x0

    iput v0, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    iput v0, p0, Landroidx/appcompat/view/menu/ly;->B0:I

    iget-object v1, p0, Landroidx/appcompat/view/menu/lf;->K:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    iget-object v1, p0, Landroidx/appcompat/view/menu/lf;->K:Ljava/util/ArrayList;

    iget-object v2, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v1, p0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    array-length v1, v1

    :goto_0
    if-ge v0, v1, :cond_0

    iget-object v2, p0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    iget-object v3, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    aput-object v3, v2, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method


# virtual methods
.method public J0(Landroidx/appcompat/view/menu/d90;)V
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/d90;->x(Ljava/lang/Object;)I

    move-result p1

    iget v0, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_1

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/lf;->F0(I)V

    invoke-virtual {p0, v2}, Landroidx/appcompat/view/menu/lf;->G0(I)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->v()I

    move-result p1

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/lf;->h0(I)V

    invoke-virtual {p0, v2}, Landroidx/appcompat/view/menu/lf;->E0(I)V

    goto :goto_0

    :cond_1
    invoke-virtual {p0, v2}, Landroidx/appcompat/view/menu/lf;->F0(I)V

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/lf;->G0(I)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lf;->P()I

    move-result p1

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/lf;->E0(I)V

    invoke-virtual {p0, v2}, Landroidx/appcompat/view/menu/lf;->h0(I)V

    :goto_0
    return-void
.end method

.method public K0()I
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    return v0
.end method

.method public L0()I
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/ly;->x0:I

    return v0
.end method

.method public M0()I
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/ly;->y0:I

    return v0
.end method

.method public N0()F
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/ly;->w0:F

    return v0
.end method

.method public O0(I)V
    .locals 2

    const/4 v0, -0x1

    if-le p1, v0, :cond_0

    const/high16 v1, -0x40800000    # -1.0f

    iput v1, p0, Landroidx/appcompat/view/menu/ly;->w0:F

    iput p1, p0, Landroidx/appcompat/view/menu/ly;->x0:I

    iput v0, p0, Landroidx/appcompat/view/menu/ly;->y0:I

    :cond_0
    return-void
.end method

.method public P0(I)V
    .locals 2

    const/4 v0, -0x1

    if-le p1, v0, :cond_0

    const/high16 v1, -0x40800000    # -1.0f

    iput v1, p0, Landroidx/appcompat/view/menu/ly;->w0:F

    iput v0, p0, Landroidx/appcompat/view/menu/ly;->x0:I

    iput p1, p0, Landroidx/appcompat/view/menu/ly;->y0:I

    :cond_0
    return-void
.end method

.method public Q0(F)V
    .locals 1

    const/high16 v0, -0x40800000    # -1.0f

    cmpl-float v0, p1, v0

    if-lez v0, :cond_0

    iput p1, p0, Landroidx/appcompat/view/menu/ly;->w0:F

    const/4 p1, -0x1

    iput p1, p0, Landroidx/appcompat/view/menu/ly;->x0:I

    iput p1, p0, Landroidx/appcompat/view/menu/ly;->y0:I

    :cond_0
    return-void
.end method

.method public R0(I)V
    .locals 3

    iget v0, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    if-ne v0, p1, :cond_0

    return-void

    :cond_0
    iput p1, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    iget-object p1, p0, Landroidx/appcompat/view/menu/lf;->K:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    iget p1, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    const/4 v0, 0x1

    if-ne p1, v0, :cond_1

    iget-object p1, p0, Landroidx/appcompat/view/menu/lf;->B:Landroidx/appcompat/view/menu/jf;

    iput-object p1, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    goto :goto_0

    :cond_1
    iget-object p1, p0, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    iput-object p1, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    :goto_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/lf;->K:Ljava/util/ArrayList;

    iget-object v0, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object p1, p0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    array-length p1, p1

    const/4 v0, 0x0

    :goto_1
    if-ge v0, p1, :cond_2

    iget-object v1, p0, Landroidx/appcompat/view/menu/lf;->J:[Landroidx/appcompat/view/menu/jf;

    iget-object v2, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    aput-object v2, v1, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_2
    return-void
.end method

.method public f(Landroidx/appcompat/view/menu/d90;)V
    .locals 8

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lf;->G()Landroidx/appcompat/view/menu/lf;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/mf;

    if-nez v0, :cond_0

    return-void

    :cond_0
    sget-object v1, Landroidx/appcompat/view/menu/jf$b;->n:Landroidx/appcompat/view/menu/jf$b;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/lf;->m(Landroidx/appcompat/view/menu/jf$b;)Landroidx/appcompat/view/menu/jf;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/jf$b;->p:Landroidx/appcompat/view/menu/jf$b;

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/lf;->m(Landroidx/appcompat/view/menu/jf$b;)Landroidx/appcompat/view/menu/jf;

    move-result-object v2

    iget-object v3, p0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v3, :cond_1

    iget-object v3, v3, Landroidx/appcompat/view/menu/lf;->M:[Landroidx/appcompat/view/menu/lf$b;

    aget-object v3, v3, v5

    sget-object v6, Landroidx/appcompat/view/menu/lf$b;->n:Landroidx/appcompat/view/menu/lf$b;

    if-ne v3, v6, :cond_1

    move v3, v4

    goto :goto_0

    :cond_1
    move v3, v5

    :goto_0
    iget v6, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    if-nez v6, :cond_3

    sget-object v1, Landroidx/appcompat/view/menu/jf$b;->o:Landroidx/appcompat/view/menu/jf$b;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/lf;->m(Landroidx/appcompat/view/menu/jf$b;)Landroidx/appcompat/view/menu/jf;

    move-result-object v1

    sget-object v2, Landroidx/appcompat/view/menu/jf$b;->q:Landroidx/appcompat/view/menu/jf$b;

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/lf;->m(Landroidx/appcompat/view/menu/jf$b;)Landroidx/appcompat/view/menu/jf;

    move-result-object v2

    iget-object v0, p0, Landroidx/appcompat/view/menu/lf;->N:Landroidx/appcompat/view/menu/lf;

    if-eqz v0, :cond_2

    iget-object v0, v0, Landroidx/appcompat/view/menu/lf;->M:[Landroidx/appcompat/view/menu/lf$b;

    aget-object v0, v0, v4

    sget-object v3, Landroidx/appcompat/view/menu/lf$b;->n:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v3, :cond_2

    goto :goto_1

    :cond_2
    move v4, v5

    :goto_1
    move v3, v4

    :cond_3
    iget v0, p0, Landroidx/appcompat/view/menu/ly;->x0:I

    const/16 v4, 0x8

    const/4 v6, -0x1

    const/4 v7, 0x5

    if-eq v0, v6, :cond_4

    iget-object v0, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v0

    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v1

    iget v6, p0, Landroidx/appcompat/view/menu/ly;->x0:I

    invoke-virtual {p1, v0, v1, v6, v4}, Landroidx/appcompat/view/menu/d90;->e(Landroidx/appcompat/view/menu/uv0;Landroidx/appcompat/view/menu/uv0;II)Landroidx/appcompat/view/menu/o4;

    if-eqz v3, :cond_6

    invoke-virtual {p1, v2}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v1

    invoke-virtual {p1, v1, v0, v5, v7}, Landroidx/appcompat/view/menu/d90;->h(Landroidx/appcompat/view/menu/uv0;Landroidx/appcompat/view/menu/uv0;II)V

    goto :goto_2

    :cond_4
    iget v0, p0, Landroidx/appcompat/view/menu/ly;->y0:I

    if-eq v0, v6, :cond_5

    iget-object v0, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v0

    invoke-virtual {p1, v2}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v2

    iget v6, p0, Landroidx/appcompat/view/menu/ly;->y0:I

    neg-int v6, v6

    invoke-virtual {p1, v0, v2, v6, v4}, Landroidx/appcompat/view/menu/d90;->e(Landroidx/appcompat/view/menu/uv0;Landroidx/appcompat/view/menu/uv0;II)Landroidx/appcompat/view/menu/o4;

    if-eqz v3, :cond_6

    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v1

    invoke-virtual {p1, v0, v1, v5, v7}, Landroidx/appcompat/view/menu/d90;->h(Landroidx/appcompat/view/menu/uv0;Landroidx/appcompat/view/menu/uv0;II)V

    invoke-virtual {p1, v2, v0, v5, v7}, Landroidx/appcompat/view/menu/d90;->h(Landroidx/appcompat/view/menu/uv0;Landroidx/appcompat/view/menu/uv0;II)V

    goto :goto_2

    :cond_5
    iget v0, p0, Landroidx/appcompat/view/menu/ly;->w0:F

    const/high16 v1, -0x40800000    # -1.0f

    cmpl-float v0, v0, v1

    if-eqz v0, :cond_6

    iget-object v0, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v0

    invoke-virtual {p1, v2}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v1

    iget v2, p0, Landroidx/appcompat/view/menu/ly;->w0:F

    invoke-static {p1, v0, v1, v2}, Landroidx/appcompat/view/menu/d90;->s(Landroidx/appcompat/view/menu/d90;Landroidx/appcompat/view/menu/uv0;Landroidx/appcompat/view/menu/uv0;F)Landroidx/appcompat/view/menu/o4;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/d90;->d(Landroidx/appcompat/view/menu/o4;)V

    :cond_6
    :goto_2
    return-void
.end method

.method public g()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public m(Landroidx/appcompat/view/menu/jf$b;)Landroidx/appcompat/view/menu/jf;
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/ly$a;->a:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v0, v0, v1

    packed-switch v0, :pswitch_data_0

    goto :goto_0

    :pswitch_0
    const/4 p1, 0x0

    return-object p1

    :pswitch_1
    iget v0, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    if-nez v0, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    return-object p1

    :pswitch_2
    iget v0, p0, Landroidx/appcompat/view/menu/ly;->A0:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/ly;->z0:Landroidx/appcompat/view/menu/jf;

    return-object p1

    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/AssertionError;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method
