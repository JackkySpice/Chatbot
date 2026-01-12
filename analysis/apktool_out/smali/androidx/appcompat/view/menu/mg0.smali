.class public abstract Landroidx/appcompat/view/menu/mg0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static a:[Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x3

    new-array v0, v0, [Z

    sput-object v0, Landroidx/appcompat/view/menu/mg0;->a:[Z

    return-void
.end method

.method public static a(Landroidx/appcompat/view/menu/mf;Landroidx/appcompat/view/menu/d90;Landroidx/appcompat/view/menu/lf;)V
    .locals 6

    const/4 v0, -0x1

    iput v0, p2, Landroidx/appcompat/view/menu/lf;->j:I

    iput v0, p2, Landroidx/appcompat/view/menu/lf;->k:I

    iget-object v0, p0, Landroidx/appcompat/view/menu/lf;->M:[Landroidx/appcompat/view/menu/lf$b;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    sget-object v2, Landroidx/appcompat/view/menu/lf$b;->n:Landroidx/appcompat/view/menu/lf$b;

    const/4 v3, 0x2

    if-eq v0, v2, :cond_0

    iget-object v0, p2, Landroidx/appcompat/view/menu/lf;->M:[Landroidx/appcompat/view/menu/lf$b;

    aget-object v0, v0, v1

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->p:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v1, :cond_0

    iget-object v0, p2, Landroidx/appcompat/view/menu/lf;->B:Landroidx/appcompat/view/menu/jf;

    iget v0, v0, Landroidx/appcompat/view/menu/jf;->e:I

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lf;->P()I

    move-result v1

    iget-object v4, p2, Landroidx/appcompat/view/menu/lf;->D:Landroidx/appcompat/view/menu/jf;

    iget v4, v4, Landroidx/appcompat/view/menu/jf;->e:I

    sub-int/2addr v1, v4

    iget-object v4, p2, Landroidx/appcompat/view/menu/lf;->B:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v4}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v5

    iput-object v5, v4, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    iget-object v4, p2, Landroidx/appcompat/view/menu/lf;->D:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v4}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v5

    iput-object v5, v4, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    iget-object v4, p2, Landroidx/appcompat/view/menu/lf;->B:Landroidx/appcompat/view/menu/jf;

    iget-object v4, v4, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    invoke-virtual {p1, v4, v0}, Landroidx/appcompat/view/menu/d90;->f(Landroidx/appcompat/view/menu/uv0;I)V

    iget-object v4, p2, Landroidx/appcompat/view/menu/lf;->D:Landroidx/appcompat/view/menu/jf;

    iget-object v4, v4, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    invoke-virtual {p1, v4, v1}, Landroidx/appcompat/view/menu/d90;->f(Landroidx/appcompat/view/menu/uv0;I)V

    iput v3, p2, Landroidx/appcompat/view/menu/lf;->j:I

    invoke-virtual {p2, v0, v1}, Landroidx/appcompat/view/menu/lf;->k0(II)V

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/lf;->M:[Landroidx/appcompat/view/menu/lf$b;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    if-eq v0, v2, :cond_3

    iget-object v0, p2, Landroidx/appcompat/view/menu/lf;->M:[Landroidx/appcompat/view/menu/lf$b;

    aget-object v0, v0, v1

    sget-object v1, Landroidx/appcompat/view/menu/lf$b;->p:Landroidx/appcompat/view/menu/lf$b;

    if-ne v0, v1, :cond_3

    iget-object v0, p2, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    iget v0, v0, Landroidx/appcompat/view/menu/jf;->e:I

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/lf;->v()I

    move-result p0

    iget-object v1, p2, Landroidx/appcompat/view/menu/lf;->E:Landroidx/appcompat/view/menu/jf;

    iget v1, v1, Landroidx/appcompat/view/menu/jf;->e:I

    sub-int/2addr p0, v1

    iget-object v1, p2, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v2

    iput-object v2, v1, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    iget-object v1, p2, Landroidx/appcompat/view/menu/lf;->E:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v2

    iput-object v2, v1, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    iget-object v1, p2, Landroidx/appcompat/view/menu/lf;->C:Landroidx/appcompat/view/menu/jf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    invoke-virtual {p1, v1, v0}, Landroidx/appcompat/view/menu/d90;->f(Landroidx/appcompat/view/menu/uv0;I)V

    iget-object v1, p2, Landroidx/appcompat/view/menu/lf;->E:Landroidx/appcompat/view/menu/jf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    invoke-virtual {p1, v1, p0}, Landroidx/appcompat/view/menu/d90;->f(Landroidx/appcompat/view/menu/uv0;I)V

    iget v1, p2, Landroidx/appcompat/view/menu/lf;->Y:I

    if-gtz v1, :cond_1

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/lf;->O()I

    move-result v1

    const/16 v2, 0x8

    if-ne v1, v2, :cond_2

    :cond_1
    iget-object v1, p2, Landroidx/appcompat/view/menu/lf;->F:Landroidx/appcompat/view/menu/jf;

    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/d90;->q(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uv0;

    move-result-object v2

    iput-object v2, v1, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    iget-object v1, p2, Landroidx/appcompat/view/menu/lf;->F:Landroidx/appcompat/view/menu/jf;

    iget-object v1, v1, Landroidx/appcompat/view/menu/jf;->g:Landroidx/appcompat/view/menu/uv0;

    iget v2, p2, Landroidx/appcompat/view/menu/lf;->Y:I

    add-int/2addr v2, v0

    invoke-virtual {p1, v1, v2}, Landroidx/appcompat/view/menu/d90;->f(Landroidx/appcompat/view/menu/uv0;I)V

    :cond_2
    iput v3, p2, Landroidx/appcompat/view/menu/lf;->k:I

    invoke-virtual {p2, v0, p0}, Landroidx/appcompat/view/menu/lf;->z0(II)V

    :cond_3
    return-void
.end method

.method public static final b(II)Z
    .locals 0

    and-int/2addr p0, p1

    if-ne p0, p1, :cond_0

    const/4 p0, 0x1

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    return p0
.end method
