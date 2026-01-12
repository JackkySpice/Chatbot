.class public abstract Landroidx/appcompat/view/menu/hy0;
.super Landroidx/appcompat/view/menu/yg;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/hx;


# instance fields
.field public final p:I


# direct methods
.method public constructor <init>(ILandroidx/appcompat/view/menu/wg;)V
    .locals 0

    invoke-direct {p0, p2}, Landroidx/appcompat/view/menu/yg;-><init>(Landroidx/appcompat/view/menu/wg;)V

    iput p1, p0, Landroidx/appcompat/view/menu/hy0;->p:I

    return-void
.end method


# virtual methods
.method public e()I
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/hy0;->p:I

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/x7;->c()Landroidx/appcompat/view/menu/wg;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {p0}, Landroidx/appcompat/view/menu/zn0;->e(Landroidx/appcompat/view/menu/hx;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "renderLambdaToString(this)"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    invoke-super {p0}, Landroidx/appcompat/view/menu/x7;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_0
    return-object v0
.end method
