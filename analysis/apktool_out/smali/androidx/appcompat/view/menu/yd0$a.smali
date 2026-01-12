.class public Landroidx/appcompat/view/menu/yd0$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/xd0$b;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/yd0;-><init>(Landroidx/appcompat/view/menu/yd0$c;Landroidx/appcompat/view/menu/xd0;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/yd0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/yd0;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/yd0$a;->a:Landroidx/appcompat/view/menu/yd0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/String;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/yd0$a;->a:Landroidx/appcompat/view/menu/yd0;

    invoke-static {v0}, Landroidx/appcompat/view/menu/yd0;->b(Landroidx/appcompat/view/menu/yd0;)Landroidx/appcompat/view/menu/yd0$c;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/yd0$a;->a:Landroidx/appcompat/view/menu/yd0;

    invoke-static {v1, p1}, Landroidx/appcompat/view/menu/yd0;->a(Landroidx/appcompat/view/menu/yd0;Ljava/lang/String;)Landroid/view/PointerIcon;

    move-result-object p1

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/yd0$c;->setPointerIcon(Landroid/view/PointerIcon;)V

    return-void
.end method
