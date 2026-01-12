.class public final Landroidx/appcompat/view/menu/li$b;
.super Landroidx/appcompat/view/menu/lb0$c;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/li;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# instance fields
.field public final w:Landroid/graphics/RectF;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/li$b;)V
    .locals 0

    .line 4
    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/lb0$c;-><init>(Landroidx/appcompat/view/menu/lb0$c;)V

    .line 5
    iget-object p1, p1, Landroidx/appcompat/view/menu/li$b;->w:Landroid/graphics/RectF;

    iput-object p1, p0, Landroidx/appcompat/view/menu/li$b;->w:Landroid/graphics/RectF;

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/li$b;Landroidx/appcompat/view/menu/li$a;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/li$b;-><init>(Landroidx/appcompat/view/menu/li$b;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/ot0;Landroid/graphics/RectF;)V
    .locals 1

    const/4 v0, 0x0

    .line 3
    invoke-direct {p0, p1, v0}, Landroidx/appcompat/view/menu/lb0$c;-><init>(Landroidx/appcompat/view/menu/ot0;Landroidx/appcompat/view/menu/mn;)V

    iput-object p2, p0, Landroidx/appcompat/view/menu/li$b;->w:Landroid/graphics/RectF;

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ot0;Landroid/graphics/RectF;Landroidx/appcompat/view/menu/li$a;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1, p2}, Landroidx/appcompat/view/menu/li$b;-><init>(Landroidx/appcompat/view/menu/ot0;Landroid/graphics/RectF;)V

    return-void
.end method

.method public static synthetic a(Landroidx/appcompat/view/menu/li$b;)Landroid/graphics/RectF;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/li$b;->w:Landroid/graphics/RectF;

    return-object p0
.end method


# virtual methods
.method public newDrawable()Landroid/graphics/drawable/Drawable;
    .locals 1

    invoke-static {p0}, Landroidx/appcompat/view/menu/li;->e0(Landroidx/appcompat/view/menu/li$b;)Landroidx/appcompat/view/menu/li;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lb0;->invalidateSelf()V

    return-object v0
.end method
