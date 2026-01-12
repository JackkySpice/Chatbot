.class public Landroidx/appcompat/view/menu/li$c;
.super Landroidx/appcompat/view/menu/li;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/li;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "c"
.end annotation


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/li$b;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Landroidx/appcompat/view/menu/li;-><init>(Landroidx/appcompat/view/menu/li$b;Landroidx/appcompat/view/menu/li$a;)V

    return-void
.end method


# virtual methods
.method public r(Landroid/graphics/Canvas;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    invoke-virtual {v0}, Landroid/graphics/RectF;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-super {p0, p1}, Landroidx/appcompat/view/menu/lb0;->r(Landroid/graphics/Canvas;)V

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    iget-object v0, p0, Landroidx/appcompat/view/menu/li;->y:Landroidx/appcompat/view/menu/li$b;

    invoke-static {v0}, Landroidx/appcompat/view/menu/li$b;->a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/graphics/Canvas;->clipOutRect(Landroid/graphics/RectF;)Z

    invoke-super {p0, p1}, Landroidx/appcompat/view/menu/lb0;->r(Landroid/graphics/Canvas;)V

    invoke-virtual {p1}, Landroid/graphics/Canvas;->restore()V

    :goto_0
    return-void
.end method
